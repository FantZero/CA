package com.webank.cert.mgr.web;

import com.webank.cert.mgr.model.BaseResponse;
import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.model.vo.CertVO;
import com.webank.cert.mgr.service.CertMgrService;
import io.swagger.annotations.*;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

/**
 * @author jiangzhe
 * @create 2021/10/20 16:07
 */

@Api("证书服务接口列表")
@RestController
@RequestMapping("cert")
public class CertMgrController {

    @Autowired
    CertMgrService certMgrService;

    //------上传------
    @ApiOperation("上传私钥")
    @ApiImplicitParams({
            @ApiImplicitParam(name="priAlg", value="证书表Id", dataType = "string", required=true),
            @ApiImplicitParam(name="priKeyStr", value="私钥串", dataType = "string", required=true),
            @ApiImplicitParam(name="userId", value="userId", dataType = "string", required=true),
    })
    @GetMapping("uploadPriKey")
    public BaseResponse uploadPriKey(@RequestParam("priAlg") String priAlg,
                                     @RequestParam("priKeyStr") String priKeyStr,
                                     @RequestParam("userId") String userId) {
        return certMgrService.uploadPriKey(priAlg, priKeyStr, userId);
    }

    @ApiOperation("上传证书")
    @PostMapping("uploadCert")
    public BaseResponse uploadCert(@RequestBody CertKeyInfo certKeyInfo,
                                   @RequestBody CertInfo certInfo) {
        return certMgrService.uploadCert(certKeyInfo, certInfo);
    }

    //------生成私钥------
    @ApiOperation("生成RSA私钥")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true)
    })
    @GetMapping("geneRSAPriKey")
    public BaseResponse<Long> geneRSAPriKey(@RequestParam("userId") String userId) {
        return certMgrService.geneRSAPriKey(userId);
    }

    @ApiOperation("生成ECDSA私钥")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true)
    })
    @GetMapping("geneECDSAPriKey")
    public BaseResponse<Long> geneECDSAPriKey(@RequestParam("userId") String userId) {
        return certMgrService.geneECDSAPriKey(userId);
    }

    @ApiOperation("生成SM2私钥")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true)
    })
    @GetMapping("geneSM2PriKey")
    public BaseResponse<Long> geneSM2PriKey(@RequestParam("userId") String userId) {
        return certMgrService.geneSM2PriKey(userId);
    }

    //------证书签发------
    @ApiOperation("（根证书）自签")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "priKey_root_id", value = "根私钥id", dataType = "string", required = true),
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true),
            @ApiImplicitParam(name = "commonName", value = "公共名", dataType = "string", required = true),
            @ApiImplicitParam(name = "organizationName", value = "组织名", dataType = "string", required = true),
            @ApiImplicitParam(name = "keyUsage", value = "证书keyUsage(选填)", dataType = "int", required = true)
    })
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

    @ApiOperation("生成证书签发请求（CSR）")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "priKey_root_id", value = "根私钥id", dataType = "int", required = true),
            @ApiImplicitParam(name = "parentCertId", value = "父证书Id", dataType = "int", required = true),
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true),
            @ApiImplicitParam(name = "commonName", value = "公共名", dataType = "string", required = true),
            @ApiImplicitParam(name = "organizationName", value = "组织名", dataType = "string", required = true),
    })
    @GetMapping("geneCertRequest")
    public BaseResponse<Long> geneCertRequest(@RequestParam("priKey_child_id") Integer priKey_child_id,
                                              @RequestParam("parentCertId") Integer parentCertId,
                                              @RequestParam("userId") String userId,
                                              @RequestParam("commonName") String commonName,
                                              @RequestParam("organizationName") String organizationName) {
        return certMgrService.geneCertRequest(priKey_child_id, parentCertId, userId, commonName, organizationName);
    }

    @ApiOperation("证书签发")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true),
            @ApiImplicitParam(name = "csr_id", value = "子证书请求Id", dataType = "int", required = true),
            @ApiImplicitParam(name = "isCaCert", value = "子证书是否可向下签发", dataType = "boolean", required = true),
            @ApiImplicitParam(name = "keyUsage", value = "证书keyUsage(选填)", dataType = "int", required = true),
    })
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

    //------CRUD------
    @ApiOperation("查询证书列表")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "issuerKeyId", value = "根证书pk_id", dataType = "int", required = true),
            @ApiImplicitParam(name = "isCACert", value = "子证书是否可向下签发", dataType = "boolean", required = true),
    })
    @GetMapping("queryCertList")
    public BaseResponse<List> queryCertList(@RequestParam("issuerKeyId")Integer issuerKeyId, @RequestParam("isCACert")Boolean isCACert) {
        return certMgrService.queryCertList(issuerKeyId, isCACert);
    }

    @ApiOperation("查询子证书请求列表")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true),
    })
    @GetMapping("queryCSRList")
    public BaseResponse<List> queryCSRList(@RequestParam("userId")String userId) {
        return certMgrService.queryCSRList(userId);
    }

    @ApiOperation("查询私钥列表")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "userId", value = "userId", dataType = "string", required = true),
    })
    @GetMapping("queryPriKeyList")
    public BaseResponse<List<CertKeyInfo>> queryPriKeyList(@RequestParam("userId")String userId) {
        return certMgrService.queryPriKeyList(userId);
    }

    @ApiOperation("查询私钥")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "priKeyId", value = "私钥Id", dataType = "long", required = true),
    })
    @GetMapping("queryPriKey")
    public BaseResponse<CertKeyInfo> queryPriKey(@RequestParam("priKeyId")Long priKeyId) {
        return certMgrService.queryPriKey(priKeyId);
    }

    @ApiOperation("下载证书（拿到证书 content）")
    @ApiImplicitParams({
            @ApiImplicitParam(name="certId", value="证书表Id", dataType = "long", required=true, paramType="query"),
    })
    @GetMapping("downloadCert")
    public BaseResponse<String> downloadCert(@RequestParam("certId") Long certId) {
        return certMgrService.downloadCert(certId);
    }

    @ApiOperation("批量删除私钥")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "priKeyIds", allowMultiple = true, value = "私钥Id数组", dataType = "long", required = true),
    })
    @PostMapping("delPriKey")
    public BaseResponse<Boolean> deleteKey(@RequestBody Long[] priKeyIds) {
        try{
            return certMgrService.deleteKeys(Arrays.asList(priKeyIds));
        }catch (Exception e){
            return BaseResponse.error("10004", "deleteKey: " + e.getMessage(), Boolean.FALSE);
        }
    }

    @PostMapping("deleteCert")
    public BaseResponse<Boolean> deleteCert(@RequestBody Long[] certIds) {
        try{
            return certMgrService.deleteCerts(Arrays.asList(certIds));
        }catch (Exception e){
            return BaseResponse.error("10004", "deleteCert: " + e.getMessage(), Boolean.FALSE);
        }
    }

    @PostMapping("deleteRequest")
    public BaseResponse<Boolean> deleteRequest(@RequestBody Long[] requestIds) {
        try{
            return certMgrService.deleteRequests(Arrays.asList(requestIds));
        }catch (Exception e){
            return BaseResponse.error("10004", "deleteRequest: " + e.getMessage(), Boolean.FALSE);
        }
    }

    //------辅助------
    @GetMapping("verify")
    public boolean verify(@RequestParam("root_cert_content")String root_cert_content,
                          @RequestParam("chain_cert_contents")List<String> chain_cert_contents) throws CertificateException{
        return certMgrService.verify(root_cert_content, chain_cert_contents);
    }
}
