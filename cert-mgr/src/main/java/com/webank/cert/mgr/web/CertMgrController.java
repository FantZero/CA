package com.webank.cert.mgr.web;

import com.webank.cert.mgr.model.BaseResponse;
import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.model.vo.CertVO;
import com.webank.cert.mgr.service.CertMgrService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateException;
import java.util.List;

/**
 * @author jiangzhe
 * @create 2021/10/20 16:07
 */

@Api("证书服务接口列表")
@RestController
public class CertMgrController {

    @Autowired
    CertMgrService certMgrService;

    @GetMapping("uploadPriKey")
    public BaseResponse uploadPriKey(@RequestParam("priAlg") String priAlg,
                                     @RequestParam("priKeyStr") String priKeyStr,
                                     @RequestParam("userId") String userId) {
        return certMgrService.uploadPriKey(priAlg, priKeyStr, userId);
    }

    @PostMapping("uploadCert")
    public BaseResponse uploadCert(@RequestBody CertKeyInfo certKeyInfo,
                                   @RequestBody CertInfo certInfo) {
        return certMgrService.uploadCert(certKeyInfo, certInfo);
    }

    @GetMapping("geneRSAPriKey")
    public BaseResponse<Long> geneRSAPriKey(@RequestParam("userId") String userId) {
        return certMgrService.geneRSAPriKey(userId);
    }

    @GetMapping("geneECDSAPriKey")
    public BaseResponse<Long> geneECDSAPriKey(@RequestParam("userId") String userId) {
        return certMgrService.geneECDSAPriKey(userId);
    }

    /**
     * 生成(国密)SM2私钥
     * @param userId
     * @return
     */
    @GetMapping("geneSM2PriKey")
    public BaseResponse<Long> geneSM2PriKey(@RequestParam("userId") String userId) {
        return certMgrService.geneSM2PriKey(userId);
    }

    /**
     * （根证书）自签
     * @param priKey_root_id 根私钥id
     * @param userId
     * @param commonName
     * @param organizationName
     * @param keyUsage 证书keyUsage(选填)
     * @return
     */
    @GetMapping("selfSignAndIssue")
    public BaseResponse<CertVO> selfSignAndIssue(@RequestParam("priKey_root_id") Integer priKey_root_id,
                                                  @RequestParam("userId") String userId,
                                                  @RequestParam("commonName") String commonName,
                                                  @RequestParam("organizationName") String organizationName,
                                                 @RequestParam("keyUsage") Integer keyUsage) {
        if(keyUsage!=null && keyUsage!=0){
            return certMgrService.selfSignAndIssue(priKey_root_id, userId, commonName, organizationName, new KeyUsage(keyUsage));
        }
        return certMgrService.selfSignAndIssue(priKey_root_id, userId, commonName, organizationName);
    }

    /**
     * 生成证书签发请求（CSR）
     * @param priKey_child_id 私钥id
     * @param parentCertId 父证书id
     * @param userId
     * @param commonName
     * @param organizationName
     * @return requestInfo.pk_id 证书请求表id
     */
    @GetMapping("geneCertRequest")
    public BaseResponse<Long> geneCertRequest(@RequestParam("priKey_child_id") Integer priKey_child_id,
                                        @RequestParam("parentCertId") Integer parentCertId,
                                        @RequestParam("userId") String userId,
                                        @RequestParam("commonName") String commonName,
                                        @RequestParam("organizationName") String organizationName) {
        return certMgrService.geneCertRequest(priKey_child_id, parentCertId, userId, commonName, organizationName);
    }

    /**
     * 证书签发
     * @param userId
     * @param csr_id
     * @param isCaCert 子证书是否可向下签发
     * @param keyUsage 证书keyUsage(选填)
     * @return
     */
    @GetMapping("signAndIssue")
    public BaseResponse<CertVO> signAndIssue(@RequestParam("userId") String userId,
                                     @RequestParam("csr_id") Integer csr_id,
                                     @RequestParam("isCaCert") boolean isCaCert,
                                    @RequestParam("keyUsage") Integer keyUsage) {
        if(keyUsage!=null && keyUsage!=0){
            return certMgrService.signAndIssue(userId, csr_id, isCaCert, new KeyUsage(keyUsage));
        }
        return certMgrService.signAndIssue(userId, csr_id, isCaCert);
    }

    @GetMapping("queryCertList")
    public BaseResponse<List> queryCertList(@RequestParam("issuerKeyId")Integer issuerKeyId, @RequestParam("isCACert")Boolean isCACert) {
        return certMgrService.queryCertList(issuerKeyId, isCACert);
    }

    @GetMapping("queryCSRList")
    public BaseResponse<List> queryCSRList(@RequestParam("userId")String userId) {
        return certMgrService.queryCSRList(userId);
    }

    @GetMapping("queryPriKeyList")
    public BaseResponse<List<CertKeyInfo>> queryPriKeyList(@RequestParam("userId")String userId) {
        return certMgrService.queryPriKeyList(userId);
    }

    @ApiOperation("下载证书（拿到证书 content）")
    @ApiImplicitParams({
            @ApiImplicitParam(name="certId", value="证书表Id'", dataType = "long", required=true, paramType="query"),
    })
    @GetMapping("downloadCert")
    public BaseResponse<String> downloadCert(@RequestParam("certId") Long certId) {
        return certMgrService.downloadCert(certId);
    }

    @GetMapping("verify")
    public boolean verify(@RequestParam("root_cert_content")String root_cert_content,
                          @RequestParam("chain_cert_contents")List<String> chain_cert_contents) throws CertificateException{
        return certMgrService.verify(root_cert_content, chain_cert_contents);
    }
}
