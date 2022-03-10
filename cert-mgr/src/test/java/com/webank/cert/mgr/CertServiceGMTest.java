package com.webank.cert.mgr;

import com.webank.cert.mgr.service.CertMgrService;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.Security;

/**
 * @author jiangzhe
 * @create 2021/11/30 13:22
 */
public class CertServiceGMTest extends BaseTest{

    @Autowired
    private CertMgrService certMgrService;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    @Test
    public void testGenSM2PriKey(){
        String userId = "deqweasdaew"; // parent/child
        int n = 1 + 1 + 4*2;   // 1根+1机构+4节点(加密)
        for (int i = 1; i <= 4; i++) {
            certMgrService.geneSM2PriKey(userId + i);
        }
    }

    @Test
    public void testSelfSignAndIssue(){
        Integer certPriKeyId = 47;
        String userId = "deqweasdaew1"; // parent
        String commonName = "chain-gm";
        String organizationName = "fisco";
        int keyUsgae = 6; // KeyUsage.keyCertSign | KeyUsage.cRLSign
        KeyUsage keyUsage = new KeyUsage(keyUsgae);
        certMgrService.selfSignAndIssue(certPriKeyId, userId, commonName, organizationName, keyUsage);
    }

    @Test
    public void testGeneCertRequest_agency(){
        Integer priKey_child_id = 48;
        Integer parentCertId = 63;
        String userId = "deqweasdaew2"; // child
        String commonName = "agency-gm";
        String organizationName = "fisco";
        certMgrService.geneCertRequest(priKey_child_id, parentCertId, userId, commonName, organizationName);
    }

    @Test
    public void signAndIssue_agency(){
        Integer csr_id = 69;
        String userId = "deqweasdaew2"; // child
        int keyUsgae = 6; // KeyUsage.keyCertSign | KeyUsage.cRLSign
        KeyUsage keyUsage = new KeyUsage(keyUsgae);
        certMgrService.signAndIssue(userId, csr_id, true, keyUsage);
    }

    @Test
    public void TestGeneCertRequest_node(){
        Integer priKey_child_id = 49;
        Integer parentCertId = 64;
        String userId = "deqweasdaew"; // child
        String commonName = "node-gm";
        String organizationName = "fisco";
        for (int i = 0; i < 2; i++) {
            certMgrService.geneCertRequest(priKey_child_id+i, parentCertId, userId+(3+i), commonName+"-"+i, organizationName);
        }
    }

    @Test
    public void signAndIssue_node(){
        String userId = "deqweasdaew"; // child
        Integer csr_id = 80;
        for (int i = 0; i < 2; i++) {
            int keyUsgae = 192; // KeyUsage.digitalSignature | KeyUsage.nonRepudiation
            KeyUsage keyUsage = new KeyUsage(keyUsgae);
            certMgrService.signAndIssue(userId+(3+i), csr_id+i, false, keyUsage);
        }
    }

    @Test
    public void TestGeneCertRequest_node_en(){
        Integer priKey_child_id = 51;
        Integer parentCertId = 64;
        String userId = "deqweasdaew"; // child
        String commonName = "node-gm-en-";
        String organizationName = "fisco";
        for (int i = 0; i < 2; i++) {
            certMgrService.geneCertRequest(priKey_child_id+i, parentCertId, userId+(5+i), commonName+i, organizationName);
        }
    }

    @Test
    public void signAndIssue_node_en(){
        String userId = "deqweasdaew"; // child
        Integer csr_id = 72;
        for (int i = 0; i < 2; i++) {
            int keyUsgae = 56; // KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement
            KeyUsage keyUsage = new KeyUsage(keyUsgae);
            certMgrService.signAndIssue(userId+(5+i), csr_id+i, false, keyUsage);
        }
    }

    @Test
    public void TestGeneCertRequest_sdk(){
        Integer priKey_child_id = 5;
        Integer parentCertId = 2;
        String userId = "deqweasdaew5"; // child
        String commonName = "sdk";
        String organizationName = "fisco";
        certMgrService.geneCertRequest(priKey_child_id, parentCertId, userId, commonName, organizationName);
    }

    @Test
    public void signAndIssue_sdk(){
        String userId = "deqweasdaew5"; // child
        Integer csr_id = 4;
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
        certMgrService.signAndIssue(userId, csr_id, false, keyUsage);
    }

    @Test
    public void signAndIssue_sdk_en(){
        String userId = "deqweasdaew5"; // child
        Integer csr_id = 4;
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement);
        certMgrService.signAndIssue(userId, csr_id, false, keyUsage);
    }
}
