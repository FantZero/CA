package com.webank.cert.mgr.service.impl;

import com.webank.cert.mgr.component.CertManager;
import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.db.cert.entity.CertRequestInfo;
import com.webank.cert.mgr.db.dao.CertDao;
import com.webank.cert.mgr.enums.KeyAlgorithmEnums;
import com.webank.cert.mgr.handler.CertHandler;
import com.webank.cert.mgr.model.BaseResponse;
import com.webank.cert.mgr.model.vo.CertVO;
import com.webank.cert.toolkit.constants.CertConstants;
import com.webank.cert.toolkit.encrypt.PemEncrypt;
import com.webank.cert.toolkit.enums.EccTypeEnums;
import com.webank.cert.toolkit.handler.ECKeyHandler;
import com.webank.cert.toolkit.handler.SM2KeyHandler;
import com.webank.cert.toolkit.model.X500NameInfo;
import com.webank.cert.toolkit.utils.CertUtils;
import com.webank.cert.toolkit.utils.KeyUtils;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.web3j.utils.Numeric;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @author jiangzhe
 * @create 2021/10/20 16:26
 */
@Service("certMgrService")
public class CertMgrServiceImpl extends CertMgrCommon{

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    @Autowired
    private CertManager certManager;

    @Autowired
    private CertDao certDao;

    @Autowired
    private CertHandler certHandler;

    /**
     * 上传私钥
     * @param priKeyAlg 私钥算法
     * @param priKeyPem 私钥pem格式字符串
     * @param userId 用户id
     * @return
     */
    @Override
    public BaseResponse uploadPriKey(String priKeyAlg, String priKeyPem, String userId) {
        CertKeyInfo certKeyInfo = new CertKeyInfo();
        certKeyInfo.setKeyAlg(priKeyAlg);
        certKeyInfo.setKeyPem(priKeyPem);
        certKeyInfo.setUserId(userId);
        return BaseResponse.success("success", certDao.save(certKeyInfo));
    }

    /**
     * 导入证书  私钥+证书
     * @param certInfo
     * @return
     */
    @Override
    public BaseResponse uploadCert(CertKeyInfo certKeyInfo, CertInfo certInfo) {
        CertKeyInfo newCertKeyInfo = certDao.save(certKeyInfo);
        certInfo.setSubjectKeyId(newCertKeyInfo.getPkId());
        return BaseResponse.success("success", certDao.save(certInfo));
    }

    /**
     * 生成私钥（RSA签名算法）
     * @param userId 传入 userId
     * @return
     */
    @Override
    public BaseResponse<Long> geneRSAPriKey(String userId){
        CryptoKeyPair cryptoKeyPair = ECKeyHandler.generateECKeyPair();
        try {
            KeyPair keyPair = KeyUtils.generateKeyPair();
            String pemPrivateKey = CertUtils.readPEMAsString(keyPair.getPrivate());
            Long certKeyId = certManager.importPrivateKey(userId, pemPrivateKey, KeyAlgorithmEnums.RSA.getKeyAlgorithm());
            return BaseResponse.success("success", certKeyId);
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10001", e.getMessage(), null);
        }
    }

    /**
     * 生成私钥（ECDSA签名算法）
     * @param userId 传入 userId
     * @return
     */
    @Override
    public BaseResponse<Long> geneECDSAPriKey(String userId){
        CryptoKeyPair cryptoKeyPair = ECKeyHandler.generateECKeyPair();
        try {
            String encryptPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()), EccTypeEnums.SECP256K1);
            Long certKeyId = certManager.importPrivateKey(userId, encryptPrivateKey, KeyAlgorithmEnums.ECDSA.getKeyAlgorithm());
            return BaseResponse.success("success", certKeyId);
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10001", e.getMessage(), null);
        }
    }

    /**
     * 生成私钥（SM2签名算法）
     * @param userId 传入 userId
     * @return
     */
    @Override
    public BaseResponse<Long> geneSM2PriKey(String userId){
        try {
            CryptoKeyPair cryptoKeyPair = SM2KeyHandler.generateSM2KeyPair();
            String encryptPrivateKey = PemEncrypt.encryptPrivateKey(Numeric.hexStringToByteArray(cryptoKeyPair.getHexPrivateKey()),
                    EccTypeEnums.SM2P256V1);
            Long certKeyId = certManager.importPrivateKey(userId, encryptPrivateKey, KeyAlgorithmEnums.SM2.getKeyAlgorithm());
            return BaseResponse.success("success", certKeyId);
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10001", e.getMessage(), null);
        }
    }

    /**
     * 自签名生成根证书
     * @param certPriKeyId 私钥id
     * @param userId 用户id
     * @param commonName 证书名
     * @param organizationName 证书所在组织名
     * @return
     */
    @Override
    public BaseResponse<CertVO> selfSignAndIssue(Integer certPriKeyId, String userId, String commonName, String organizationName) {
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName(commonName)
                .organizationName(organizationName)
                .organizationalUnitName(organizationName)
                .build();
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        try {
            CertVO cert = certManager.createRootCert(userId, certPriKeyId, issuer, beginDate, endDate);
            return BaseResponse.success("success", cert);
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10001", e.getMessage(), null);
        }
    }

    /**
     * 自签名生成根证书
     * @param certPriKeyId 私钥id
     * @param userId 用户id
     * @param commonName 证书名
     * @param organizationName 证书所在组织名
     * @param keyUsage
     * @return
     */
    @Override
    public BaseResponse<CertVO> selfSignAndIssue(Integer certPriKeyId, String userId, String commonName, String organizationName, KeyUsage keyUsage) {
        X500NameInfo issuer = X500NameInfo.builder()
                .commonName(commonName)
                .organizationName(organizationName)
                .organizationalUnitName(organizationName)
                .build();
        Date beginDate = new Date();
        Date endDate = new Date(beginDate.getTime() + CertConstants.DEFAULT_VALIDITY);
        try {
            CertVO cert = certManager.createRootCert(userId, certPriKeyId, issuer, keyUsage, beginDate, endDate);
            return BaseResponse.success("success", cert);
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10001", e.getMessage(), null);
        }
    }

    /**
     * 生成子证书请求
     * @param priKey_child_id 私钥id
     * @param parentCertId 父证书id
     * @param userId 用户id
     * @param commonName 证书名
     * @param organizationName 证书所在组织名
     * @return requestInfo.pk_id
     */
    @Override
    public BaseResponse<Long> geneCertRequest(Integer priKey_child_id, Integer parentCertId, String userId,
                                                String commonName, String organizationName) {
        X500NameInfo subject = X500NameInfo.builder()
                .commonName(commonName)
                .organizationName(organizationName)
                .organizationalUnitName(organizationName)
                .build();
        // 获取请求的私钥信息
        CertKeyInfo certKeyInfo = certDao.findCertKeyById(priKey_child_id);
        String pemPrivateKey = certKeyInfo.getKeyPem();
        // 使用请求的私钥算法
        KeyAlgorithmEnums keyAlgorithm = KeyAlgorithmEnums.getByKeyAlg(certKeyInfo.getKeyAlg());
        try {
            CertRequestInfo requestInfo = this.certHandler.createCertRequest(userId, priKey_child_id, pemPrivateKey, keyAlgorithm, parentCertId, subject);
            return BaseResponse.success("success", requestInfo.getPkId());
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10002", e.getMessage(), null);
        }
    }

    /**
     * 签发子证书
     * @param userId 用户id
     * @param csr_id 证书请求id
     * isCACert
     *     node false
     *     sdk false
     *     agency true
     *     ca true
     * @return
     */
    @Override
    public BaseResponse<CertVO> signAndIssue(String userId, Integer csr_id, boolean isCaCert) {
        try {
            return BaseResponse.success("success", certManager.createChildCert(userId, csr_id, isCaCert));
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10003", e.getMessage(), null);
        }
    }

    /**
     * 签发子证书（加密）
     * @param userId 用户id
     * @param csr_id 证书请求id
     * @param isCaCert
     *     node false
     *     sdk false
     *     agency true
     *     ca true
     * @param keyUsage
     * @return
     */
    @Override
    public BaseResponse<CertVO> signAndIssue(String userId, Integer csr_id, boolean isCaCert, KeyUsage keyUsage) {
        try {
            return BaseResponse.success("success", certManager.createChildCert(userId, csr_id, isCaCert, keyUsage));
        } catch (Exception e) {
            e.printStackTrace();
            return BaseResponse.error("10003", e.getMessage(), null);
        }
    }

    /**
     * 证书验证
     * @param root_cert_content 根证书
     * @param chain_cert_contents 子证书
     * @return
     * @throws CertificateException
     */
    @Override
    public boolean verify(String root_cert_content, List<String> chain_cert_contents) throws CertificateException {
        X509Certificate rootCertificate = CertUtils.convertStrToCert(root_cert_content);
        List<X509Certificate> chainCertificates = new ArrayList<>();
        for (String chain_cert_content: chain_cert_contents){
            chainCertificates.add(CertUtils.convertStrToCert(chain_cert_content));
        }
        return certHandler.verify(rootCertificate, chainCertificates);
    }

}
