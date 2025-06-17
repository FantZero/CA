package com.webank.cert.mgr.service.impl;

import com.webank.cert.mgr.model.BaseResponse;
import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.db.dao.CertDao;
import com.webank.cert.mgr.service.CertMgrService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * @author jiangzhe
 * @create 2021/10/21 11:23
 */
public abstract class CertMgrCommon implements CertMgrService {

    @Autowired
    private CertDao certDao;

    @Override
    public BaseResponse<String> downloadCert(Long certId) {
        CertInfo certInfo = certDao.findCertById(certId);
        return BaseResponse.success("success", certInfo.getCertContent());
    }

    @Override
    public BaseResponse<List> queryCertList(Integer issuerKeyId, Boolean isCACert) {
        return BaseResponse.success("success", certDao.findCertList(issuerKeyId, isCACert));
    }

    @Override
    public BaseResponse<List> queryCertList(String userId, Boolean isCACert) {
        return BaseResponse.success("success", certDao.findCertList(userId, isCACert));
    }

    @Override
    public BaseResponse<List> queryCSRList(String userId) {
        return BaseResponse.success("success", certDao.findCertRequestList(userId));
    }

    @Override
    public BaseResponse<List<CertKeyInfo>> queryPriKeyList(String userId) {
        return BaseResponse.success("success", certDao.findKeyByUserId(userId));
    }

    @Override
    public BaseResponse<CertKeyInfo> queryPriKey(Long priKeyId) {
        return BaseResponse.success("success", certDao.findCertKeyById(priKeyId));
    }

    /**
     * 删除私钥
     *
     * @param priKeyIds
     * @return
     */
    @Override
    @Transactional
    public BaseResponse<Boolean> deleteKeys(Iterable<Long> priKeyIds){
        try{
            certDao.deleteKeys(priKeyIds);
            return BaseResponse.success(Boolean.TRUE);
        }catch(Exception e){
            return BaseResponse.error("10004", e.getMessage(), Boolean.FALSE);
        }
    }

    /**
     * 删除证书
     *
     * @param certIds
     * @return
     */
    @Override
    @Transactional
    public BaseResponse<Boolean> deleteCerts(Iterable<Long> certIds) {
        try{
            certDao.deleteCerts(certIds);
            return BaseResponse.success(true);
        }catch(Exception e){
            return BaseResponse.error("10004", e.getMessage(), false);
        }
    }

    /**
     * 删除子证书请求
     *
     * @param requestIds
     * @return
     */
    @Override
    @Transactional
    public BaseResponse<Boolean> deleteRequests(Iterable<Long> requestIds) {
        try{
            certDao.deleteRequests(requestIds);
            return BaseResponse.success(true);
        }catch(Exception e){
            return BaseResponse.error("10004", e.getMessage(), false);
        }
    }
}
