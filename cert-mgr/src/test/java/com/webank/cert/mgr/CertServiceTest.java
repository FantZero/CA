package com.webank.cert.mgr;

import com.webank.cert.mgr.service.CertMgrService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.Security;

/**
 * @author jiangzhe
 * @create 2021/11/30 13:22
 */
public class CertServiceTest extends BaseTest{

    @Autowired
    private CertMgrService certMgrService;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    @Test
    public void testGenRSAPriKey(){
        String userId = "deqweasdaew1";
        certMgrService.geneRSAPriKey(userId);
    }

    @Test
    public void testGenECDSAPriKey(){
        String userId = "deqweasdaew1";
        certMgrService.geneECDSAPriKey(userId);
    }

    @Test
    public void testSelfSignAndIssue(){
        Integer certPriKeyId = 9;
        String userId = "deqweasdaew1";
        String commonName = "chain";
        String organizationName = "fisco";
        certMgrService.selfSignAndIssue(certPriKeyId, userId, commonName, organizationName);
    }

    @Test
    public void TestGeneCertRequest_agency(){
        Integer priKey_child_id = 10;
        Integer parentCertId = 9;
        String userId = "deqweasdaew2";
        String commonName = "agency-1";
        String organizationName = "fisco";
        certMgrService.geneCertRequest(priKey_child_id, parentCertId, userId, commonName, organizationName);
    }

    @Test
    public void signAndIssue_agency(){
        String userId = "deqweasdaew2";
        Integer csr_id = 7;
        certMgrService.signAndIssue(userId, csr_id, true);
    }

    @Test
    public void TestGeneCertRequest_node(){
        Integer priKey_child_id = 12;
        Integer parentCertId = 10;
        String userId = "deqweasdaew4";
        String commonName = "node-1";
        String organizationName = "fisco";
        certMgrService.geneCertRequest(priKey_child_id, parentCertId, userId, commonName, organizationName);
    }

    @Test
    public void signAndIssue_node(){
        String userId = "deqweasdaew4";
        Integer csr_id = 9;
        certMgrService.signAndIssue(userId, csr_id, false);
    }

    @Test
    public void TestGeneCertRequest_sdk(){
        Integer priKey_child_id = 5;
        Integer parentCertId = 2;
        String userId = "deqweasdaew5";
        String commonName = "sdk";
        String organizationName = "fisco";
        certMgrService.geneCertRequest(priKey_child_id, parentCertId, userId, commonName, organizationName);
    }

    @Test
    public void signAndIssue_sdk(){
        String userId = "deqweasdaew5";
        Integer csr_id = 4;
        certMgrService.signAndIssue(userId, csr_id, false);
    }
}
