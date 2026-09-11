package io.github.sensitivescanner.scanner;

import io.github.sensitivescanner.TestFixtures;
import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.rules.*;
import io.github.sensitivescanner.traffic.TrafficTransaction;
import org.junit.jupiter.api.Test;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import static org.junit.jupiter.api.Assertions.*;

class RuleCoverageTest {
    private Set<String> scan(TrafficTransaction transaction,ScanSettings settings){return new DetectionEngine(RuleCatalog.defaults()).scan(List.of(transaction),settings,new AtomicBoolean(),(a,b)->{}).findings().stream().map(f->f.ruleId()).collect(Collectors.toSet());}

    @Test void coversSensitiveDiscovererResourceAndIdentityFamilies(){
        String body="Contact security-team@example.invalid at 10.20.30.40 or 127.0.0.1. Storage: https://audit-data.s3.ap-northeast-2.amazonaws.com and gs://audit-bucket-safe. arn:aws:s3:::audit-bucket-safe";
        Set<String> found=scan(TestFixtures.response(body),new ScanSettings());
        assertTrue(found.containsAll(Set.of("SENSITIVE-EMAIL","SENSITIVE-PRIVATE-IP","SENSITIVE-LOOPBACK-IP","SENSITIVE-S3-BUCKET","SENSITIVE-GCS-BUCKET","SENSITIVE-AWS-ARN")),found.toString());
    }

    @Test void detectsSensitiveDiscovererCompatibleCredentialContextWithoutAcceptingPlaceholders(){
        String body="api.key => \"Zp7N4vQ2sR8xL5mT1cK9wB3\"; secret(value): 'D7kX9pQ2mL8zR4'";
        Set<String> found=scan(TestFixtures.response(body),new ScanSettings());
        assertTrue(found.contains("SENSITIVE-GENERIC-API-KEY"),found.toString());
        assertTrue(found.contains("SENSITIVE-GENERIC-SECRET"),found.toString());
        assertFalse(scan(TestFixtures.response("api.key => \"YOUR_API_KEY\""),new ScanSettings()).contains("SENSITIVE-GENERIC-API-KEY"));
    }

    @Test void detectsEnvironmentFileReferencesButIgnoresRuntimeEnvironmentAccess(){
        assertTrue(scan(TestFixtures.response("Deployment accidentally included .env.production"),new ScanSettings()).contains("SENSITIVE-ENV-REFERENCE"));
        assertFalse(scan(TestFixtures.response("const region = process.env.REGION"),new ScanSettings()).contains("SENSITIVE-ENV-REFERENCE"));
    }

    @Test void detectsSensitiveAndServerSideFileExtensionsOnlyFromRequestUrl(){
        var php=TestFixtures.transaction("GET","https://safe.invalid/archive/config.php?download=1","GET /archive/config.php?download=1 HTTP/1.1\r\nHost: safe.invalid\r\n\r\n","HTTP/1.1 200 OK\r\n\r\n");
        assertTrue(scan(php,new ScanSettings()).contains("SENSITIVE-FILE-PHP"));
        assertFalse(scan(TestFixtures.response("The documentation mentions config.php"),new ScanSettings()).contains("SENSITIVE-FILE-PHP"));
    }

    @Test void globalAndPerRuleAreasAreEnforced(){
        String value="AKIA"+"0".repeat(16);
        ScanSettings global=new ScanSettings();global.enabledAreas.remove(ScanArea.RESPONSE_BODY);
        assertFalse(scan(TestFixtures.response(value),global).contains("SENSITIVE-AWS-ACCESS-KEY"));
        ScanSettings perRule=new ScanSettings();perRule.ruleAreas.put("SENSITIVE-AWS-ACCESS-KEY",Set.of(ScanArea.REQUEST_HEADERS));
        assertFalse(scan(TestFixtures.response(value),perRule).contains("SENSITIVE-AWS-ACCESS-KEY"));
    }

    @Test void customRegexUsesSelectedAreaAndReturnsRawMatch(){
        CustomRegexRule rule=new CustomRegexRule("CUSTOM-TEST","Internal ticket","TICKET-[0-9]{4}","",Severity.LOW,Set.of(ScanArea.RESPONSE_BODY));
        var result=new DetectionEngine(List.of(rule)).scan(List.of(TestFixtures.response("TICKET-4815")),new ScanSettings(),new AtomicBoolean(),(a,b)->{});
        assertEquals("TICKET-4815",result.findings().get(0).evidence());
        assertFalse(result.findings().get(0).evidence().contains("*"));
    }
}
