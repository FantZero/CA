package com.webank.cert.mgr.service.impl;

import com.webank.cert.mgr.model.BaseResponse;
import com.webank.cert.mgr.db.cert.entity.CertInfo;
import com.webank.cert.mgr.db.cert.entity.CertKeyInfo;
import com.webank.cert.mgr.db.dao.CertDao;
import com.webank.cert.mgr.service.CertMgrService;
import org.springframework.beans.factory.annotation.Autowired;

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
}
