package com.webank.cert.mgr.service;

import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.model.BaseResponse;
import com.webank.cert.mgr.model.vo.CertVO;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.security.cert.CertificateException;
import java.util.List;

/**
 * @author jiangzhe
 * @create 2021/10/21 11:03
 *
 * 涉及到私钥的接口 需要支持 导入数据库 或 导入密码卡 的实现方法
 */
public interface CertMgrService {

    //导入私钥    到数据库/密码卡
    BaseResponse uploadPriKey(String priAlg, String priKeyStr, String userId);

    //生成私钥    保存到数据库/密码卡
    BaseResponse<Long> geneRSAPriKey(String userId);
    //生成私钥    保存到数据库/密码卡
    BaseResponse<Long> geneECDSAPriKey(String userId);
    //生成私钥    保存到数据库/密码卡
    BaseResponse<Long> geneSM2PriKey(String userId);

    //导入证书    证书+私钥 私钥选择保存到数据库/密码卡
    BaseResponse uploadCert(CertKeyInfo certKeyInfo, CertInfo certInfo);

    //自签名生成根证书    根证书私钥id
    BaseResponse<CertVO> selfSignAndIssue(Integer priKey_root_id, String userId, String commonName, String organizationName);

    //自签名生成根证书    根证书私钥id
    BaseResponse<CertVO> selfSignAndIssue(Integer certPriKeyId, String userId, String commonName, String organizationName, KeyUsage keyUsage);

    //生成子证书请求     子证书私钥id + 上级证书id
    BaseResponse<Long> geneCertRequest(Integer priKey_child_id, Integer parentCertId, String userId, String commonName, String organizationName);

    //签发子证书       单选子证书请求
    BaseResponse<CertVO> signAndIssue(String userId, Integer csr_id, boolean isCaCert);

    //签发子证书      单选子证书请求
    BaseResponse<CertVO> signAndIssue(String userId, Integer csr_id, boolean isCaCert, KeyUsage keyUsage);

    //导出证书 字符串形式
    BaseResponse<String> downloadCert(Long certId);

    //证书列表查询
    BaseResponse<List> queryCertList(Integer issuerKeyId, Boolean isCACert);

    //证书列表查询
    BaseResponse<List> queryCertList(String userId, Boolean isCACert);

    //子证书请求列表查询
    BaseResponse<List> queryCSRList(String userId);

    //证书私钥列表查询
    BaseResponse<List<CertKeyInfo>> queryPriKeyList(String userId);

    // 私钥查询
    BaseResponse<CertKeyInfo> queryPriKey(Long priKeyId);

    /**
     * 删除私钥
     * @param priKeyIds
     * @return
     */
    BaseResponse<Boolean> deleteKeys(Iterable<Long> priKeyIds);

    /**
     * 删除证书
     * @param certIds
     * @return
     */
    BaseResponse<Boolean> deleteCerts(Iterable<Long> certIds);

    /**
     * 删除子证书请求
     * @param requestIds
     * @return
     */
    BaseResponse<Boolean> deleteRequests(Iterable<Long> requestIds);

    //证书验证
    boolean verify(String root_cert_content, List<String> chain_cert_contents) throws CertificateException;
}
