package com.webank.cert.mgr.handler;

import cn.hutool.core.io.FileUtil;
import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.db.cert.entity.CertRequestInfo;
import com.webank.cert.mgr.db.dao.CertDao;
import com.webank.cert.mgr.enums.CertDigestAlgEnums;
import com.webank.cert.mgr.enums.KeyAlgorithmEnums;
import com.webank.cert.mgr.enums.MgrExceptionCodeEnums;
import com.webank.cert.mgr.exception.CertMgrException;
import com.webank.cert.toolkit.encrypt.PemEncrypt;
import com.webank.cert.toolkit.handler.ECKeyHandler;
import com.webank.cert.toolkit.handler.SM2KeyHandler;
import com.webank.cert.toolkit.handler.X509CertHandler;
import com.webank.cert.toolkit.model.X500NameInfo;
import com.webank.cert.toolkit.service.CertService;
import com.webank.cert.toolkit.utils.CertUtils;
import com.webank.cert.toolkit.utils.KeyUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.web3j.utils.Numeric;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;


/**
 * @author wesleywang
 */
@Service
@Slf4j
public class CertHandler {


    @Autowired
    private CertService certService;
    @Autowired
    private CertDao certDao;


    public long importPrivateKey(String userId, String pemPrivateKey, String priAlg) throws Exception {
        if (StringUtils.isBlank(userId)) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        CertKeyInfo certKeyInfo = new CertKeyInfo();
        certKeyInfo.setKeyAlg(priAlg);
        certKeyInfo.setKeyPem(pemPrivateKey);
        certKeyInfo.setUserId(userId);
        certKeyInfo = certDao.save(certKeyInfo);
        return certKeyInfo.getPkId();
    }

    public void deleteKey(long pkId){
        certDao.deleteKey(pkId);
    }


    @Transactional
    public CertInfo createRootCert(String userId, long certKeyId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm,
                                   X500NameInfo issuer, KeyUsage keyUsage, Date beginDate, Date endDate)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        if (certKeyId > 0 && pemPrivateKey == null) {
            CertKeyInfo certKeyInfo = certDao.findCertKeyById(certKeyId);
            pemPrivateKey = certKeyInfo.getKeyPem();
            keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(certKeyInfo.getKeyAlg());
        }
        CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair = getKeyPair(keyAlgorithm, pemPrivateKey);
        String signAlg = certDigestAlgEnums.getAlgorithmName();

        X509Certificate certificate = certService.createRootCertificate(signAlg, issuer, keyUsage, beginDate, endDate, keyPair.getPublic(), keyPair.getPrivate());
        certificate.verify(keyPair.getPublic());

        String certStr = CertUtils.readPEMAsString(certificate);
        String pubKeyStr = CertUtils.readPEMAsString(keyPair.getPublic());
        return certDao.save(buildCertInfo(certStr, issuer.getCommonName(),
                issuer.getOrganizationName(), issuer.getCommonName(), issuer.getOrganizationName(),
                pubKeyStr, userId, certificate.getSerialNumber(), certKeyId,
                certKeyId, true, 0));
    }

    @Transactional
    public CertRequestInfo createCertRequest(String userId, long certKeyId, String pemPrivateKey, KeyAlgorithmEnums keyAlgorithm,
                                             long parentCertId, X500NameInfo subject)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        if (certKeyId > 0 && pemPrivateKey == null) {
            CertKeyInfo certKeyInfo = certDao.findCertKeyById(certKeyId);
            pemPrivateKey = certKeyInfo.getKeyPem();
            keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(certKeyInfo.getKeyAlg());
        }
        CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair = getKeyPair(keyAlgorithm, pemPrivateKey);

        String signAlg = certDigestAlgEnums.getAlgorithmName();
        PKCS10CertificationRequest request = certService.createCertRequest(subject, keyPair.getPublic(), keyPair.getPrivate(), signAlg);
        String csrStr = CertUtils.readPEMAsString(request);

        CertInfo certInfo = certDao.findCertById(parentCertId);
        return certDao.save(buildCertRequestInfo(csrStr, subject.getCommonName(), subject.getOrganizationName(),
                parentCertId, userId, certKeyId, certInfo.getUserId()));
    }

    @Transactional
    public CertInfo createChildCert(String userId, int csrId, boolean isCaCert, KeyUsage keyUsage,
                                  Date beginDate, Date endDate)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        CertRequestInfo requestInfo = certDao.findCertRequestById(csrId);
        if (requestInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_REQUEST_NOT_EXIST);
        }
        CertKeyInfo keyInfo = certDao.findCertKeyById(requestInfo.getSubjectKeyId());
        if (keyInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_NOT_EXIST);
        }
        KeyAlgorithmEnums keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(keyInfo.getKeyAlg());
        KeyPair keyPair = getKeyPair(keyAlgorithm, keyInfo.getKeyPem());

        // 上一级的 cert_info
        CertInfo certInfo_P = certDao.findCertById(requestInfo.getPCertId());
        if (certInfo_P == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_NOT_EXIST);
        }
//        CertKeyInfo keyInfo = certDao.findCertKeyById(certInfo.getIssuerKeyId()); // pr
        // 上一级的 cert_key_info
        CertKeyInfo keyInfo_P = certDao.findCertKeyById(certInfo_P.getSubjectKeyId());
        if (keyInfo_P == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_NOT_EXIST);
        }

        keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(keyInfo_P.getKeyAlg());
        CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair_P = getKeyPair(keyAlgorithm, keyInfo_P.getKeyPem());

        X509Certificate parentCertificate = CertUtils.convertStrToCert(certInfo_P.getCertContent());
        try {
            parentCertificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_VALIDITY_FAILURE);
        }

        PKCS10CertificationRequest request = CertUtils.convertStrToCsr(requestInfo.getCertRequestContent());
        String signAlg = certDigestAlgEnums.getAlgorithmName();
        X509Certificate certificate = certService.createChildCertificate(isCaCert, signAlg, parentCertificate, request, keyUsage, beginDate, endDate, keyPair_P.getPrivate());
        certificate.verify(parentCertificate.getPublicKey());
        requestInfo.setIssue(true);
        certDao.save(requestInfo);

        String certStr = CertUtils.readPEMAsString(certificate);
        String pubKeyStr = CertUtils.readPEMAsString(keyPair.getPublic());
        return certDao.save(buildCertInfo(certStr, certInfo_P.getIssuerCN(),
                certInfo_P.getIssuerOrg(), requestInfo.getSubjectCN(), requestInfo.getSubjectOrg(),
                pubKeyStr, userId, certificate.getSerialNumber(), certInfo_P.getIssuerKeyId(), // pr: keyInfo_P.getPkId() -> certInfo_P.getIssuerKeyId()
                requestInfo.getSubjectKeyId(), isCaCert, certInfo_P.getPkId()));
    }

    @Transactional
    public CertInfo resetCertificate(String userId, long certId, KeyUsage keyUsage,
                                   Date beginDate, Date endDate)
            throws Exception {
        if (StringUtils.isBlank(userId)){
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_ACCOUNT_NOT_EXIST);
        }
        CertInfo certInfo = certDao.findCertById(certId);
        if (certInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_NOT_EXIST);
        }
        CertKeyInfo keyInfo = certDao.findCertKeyById(certInfo.getIssuerKeyId());
        if (keyInfo == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_NOT_EXIST);
        }

        X509Certificate certificate = CertUtils.convertStrToCert(certInfo.getCertContent());

        KeyAlgorithmEnums keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(keyInfo.getKeyAlg());
        CertDigestAlgEnums certDigestAlgEnums = getCertDigestAlg(keyAlgorithm);
        KeyPair keyPair = getKeyPair(keyAlgorithm, keyInfo.getKeyPem());

        X509Certificate reCert = null;
        if (certInfo.getSubjectKeyId().equals(certInfo.getIssuerKeyId())) {
            reCert = X509CertHandler.createRootCert(certDigestAlgEnums.getAlgorithmName(),
                    X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()), null,
                    beginDate, endDate, certificate.getPublicKey(), keyPair.getPrivate());
        } else {
            CertInfo parentCertInfo = certDao.findCertById(certInfo.getPCertId());
            if (parentCertInfo == null) {
                throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_NOT_EXIST);
            }

            CertRequestInfo requestInfo = certDao.findByPCertIdAndSubjectKeyId(
                    certInfo.getPCertId(), certInfo.getSubjectKeyId());
            if (requestInfo == null) {
                throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_REQUEST_NOT_EXIST);
            }

            X509Certificate parentCert = CertUtils.convertStrToCert(parentCertInfo.getCertContent());
            reCert = X509CertHandler.createChildCert(certInfo.getIsCACert(), certDigestAlgEnums.getAlgorithmName(),
                    parentCert, CertUtils.convertStrToCsr(requestInfo.getCertRequestContent()),
                    keyUsage, beginDate, endDate, keyPair.getPrivate());
        }

        String reCertStr = CertUtils.readPEMAsString(reCert);
        certInfo.setUserId(userId);
        certInfo.setCertContent(reCertStr);
        return certDao.save(certInfo);
    }


    public List<CertInfo> queryCertInfoList(String userId, Long issuerKeyId, Long pCertId, String issuerOrg,
                                            String issuerCN, Boolean isCACert) {

        return certDao.findCertList(userId, issuerKeyId, pCertId, issuerOrg, issuerCN, isCACert);
    }


    public List<CertRequestInfo> queryCertRequestList(String userId, Long subjectKeyId, Long pCertId,
                                                      String subjectOrg, String subjectCN, String pCertUserId) {
        return certDao.findCertRequestList(userId, subjectKeyId, pCertId, subjectOrg, subjectCN, pCertUserId);
    }

    public List<CertKeyInfo> queryCertKeyList(String userId) {
        return certDao.findKeyByUserId(userId);
    }


    public CertInfo queryCertInfoByCertId(long certId) {
        return certDao.findCertById(certId);
    }

    public CertRequestInfo queryCertRequestByCsrId(long csrId) {
        return certDao.findCertRequestById(csrId);
    }


    private CertDigestAlgEnums getCertDigestAlg(KeyAlgorithmEnums keyAlgorithm) throws CertMgrException {
        if (keyAlgorithm == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_ALG_NOT_EXIST);
        }
        CertDigestAlgEnums certDigestAlgEnums = CertDigestAlgEnums.getByKeyAlg(keyAlgorithm.getKeyAlgorithm());
        if (certDigestAlgEnums == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_ALG_NOT_EXIST);
        }
        return certDigestAlgEnums;
    }


    private KeyPair getKeyPair(KeyAlgorithmEnums keyAlgorithm, String pemPrivateKey) throws Exception {
        KeyPair keyPair = null;
        if (keyAlgorithm.equals(KeyAlgorithmEnums.ECDSA)) {
//            keyPair = KeyUtils.getECKeyPair(pemPrivateKey);  // pr
            byte[] bytes = PemEncrypt.decryptPrivateKey(pemPrivateKey);
            keyPair = ECKeyHandler.generateECKeyPair(Numeric.toHexStringNoPrefix(bytes)).getKeyPair();
        }
        if(keyAlgorithm.equals(KeyAlgorithmEnums.SM2)){     // pr
            byte[] bytes = PemEncrypt.decryptPrivateKey(pemPrivateKey);
            keyPair = SM2KeyHandler.generateSM2KeyPair(Numeric.toHexStringNoPrefix(bytes)).getKeyPair();
        }
        if (keyAlgorithm.equals(KeyAlgorithmEnums.RSA)) {
            keyPair = KeyUtils.getRSAKeyPair(pemPrivateKey);
        }
        if (keyPair == null) {
            throw new CertMgrException(MgrExceptionCodeEnums.PKEY_MGR_CERT_KEY_ALG_NOT_EXIST);
        }
        return keyPair;
    }

    public boolean verify(X509Certificate X509certificateRoot, List<X509Certificate> X509CertificateChain) {
        return certService.verify(X509certificateRoot, X509CertificateChain);
    }

    private CertInfo buildCertInfo(String certificate, String issuerCommonName, String issuerOrgName,
                                   String subjectCommonName, String subjectOrgName, String pubKeyStr,
                                   String userId, BigInteger serialNumber, long issuerKeyId, long subjectKeyId,
                                   boolean isCACert, long parentCertId) {
        CertInfo certInfo = new CertInfo();
        certInfo.setUserId(userId);
        certInfo.setIssuerKeyId(issuerKeyId);
        certInfo.setSubjectKeyId(subjectKeyId);
        certInfo.setCertContent(certificate);
        certInfo.setIssuerCN(issuerCommonName);
        certInfo.setIssuerOrg(issuerOrgName);
        certInfo.setSubjectCN(subjectCommonName);
        certInfo.setSubjectOrg(subjectOrgName);
        certInfo.setSubjectPubKey(pubKeyStr);
        certInfo.setSerialNumber(String.valueOf(serialNumber));
        certInfo.setIsCACert(isCACert);
        certInfo.setPCertId(parentCertId);
        return certInfo;
    }

    private CertRequestInfo buildCertRequestInfo(String csrStr, String commonName, String organizationName,
                                                 long parentCertId, String userId, long certKeyId, String pCertUserId) {
        CertRequestInfo certRequestInfo = new CertRequestInfo();
        certRequestInfo.setUserId(userId);
        certRequestInfo.setPCertId(parentCertId);
        certRequestInfo.setSubjectKeyId(certKeyId);
        certRequestInfo.setSubjectCN(commonName);
        certRequestInfo.setSubjectOrg(organizationName);
        certRequestInfo.setCertRequestContent(csrStr);
        certRequestInfo.setPCertUserId(pCertUserId);
        certRequestInfo.setIssue(false);
        return certRequestInfo;
    }

}
