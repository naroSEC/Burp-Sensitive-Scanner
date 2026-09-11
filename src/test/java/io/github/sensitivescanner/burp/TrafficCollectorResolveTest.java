package io.github.sensitivescanner.burp;

import io.github.sensitivescanner.TestFixtures;
import io.github.sensitivescanner.rules.RuleCatalog;
import io.github.sensitivescanner.scanner.*;
import io.github.sensitivescanner.traffic.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class TrafficCollectorResolveTest {
    @Test void restoresTheExactRepositoryTransactionAfterFindingRawDataWasOmitted(){
        String secret="D7k!xP9vQ2mL8zR4";
        TrafficTransaction login=TestFixtures.transaction("POST","https://alpha.invalid/member/login_ps.php","POST /member/login_ps.php HTTP/1.1\r\nHost: alpha.invalid\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nclient_secret="+secret,"HTTP/1.1 302 Found\r\n\r\n");
        TrafficTransaction javascript=TestFixtures.transaction("GET","https://cdn.invalid/index.js","GET /index.js HTTP/1.1\r\nHost: cdn.invalid\r\n\r\n","HTTP/1.1 200 OK\r\n\r\nfunction test(){}");
        TrafficRepository imported=new TrafficRepository(100),captured=new TrafficRepository(100);imported.add(login);captured.add(javascript);
        ScanSettings settings=new ScanSettings();settings.maximumRetainedFindingBytes=1;settings.scannerThreads=1;
        var result=new DetectionEngine(RuleCatalog.defaults()).scan(List.of(login),settings,new AtomicBoolean(),(a,b)->{});
        var finding=result.findings().stream().filter(f->f.evidence().equals(secret)).findFirst().orElseThrow();
        assertEquals(0,finding.traffic().messageBytes());
        TrafficTransaction restored=new TrafficCollector(null,captured,imported).resolve(finding.traffic(),finding.trafficKey()).orElseThrow();
        assertEquals(login.url(),restored.url());assertTrue(restored.requestText().contains("/member/login_ps.php"));assertFalse(restored.requestText().contains("/index.js"));
    }
}
