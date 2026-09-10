package io.github.sensitivescanner.scanner;

import io.github.sensitivescanner.TestFixtures;
import io.github.sensitivescanner.rules.RuleCatalog;
import io.github.sensitivescanner.traffic.TrafficTransaction;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class DetectionEngineTest {
    private final DetectionEngine engine=new DetectionEngine(RuleCatalog.defaults());
    private Set<String> rules(TrafficTransaction tx){return engine.scan(List.of(tx),new ScanSettings(),new AtomicBoolean(),(a,b)->{}).findings().stream().map(f->f.ruleId()).collect(java.util.stream.Collectors.toSet());}
    @Test void detectsTruePositiveCorpus(){
        String awsAccess="AKIA"+"0".repeat(16),github="ghp_"+"0".repeat(36),gitlab="glpat-"+"0".repeat(20);
        String privateKey="-----BEGIN "+"PRIVATE KEY-----\nZHVtbXktbm90LWEtcmVhbC1rZXktbWF0ZXJpYWw=\n-----END "+"PRIVATE KEY-----";
        String body="""
            {"aws":"%s",
             "aws_secret_access_key":"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/ab",
             "github":"%s",
             "gitlab":"%s",
             "jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.0000000000000000",
             "client_secret":"D7k!xP9vQ2mL8zR4",
             "db":"postgresql://dummy_user:D7k!xP9vQ2mL8zR4@safe.invalid/db"}
            %s
            """.formatted(awsAccess,github,gitlab,privateKey);
        Set<String> found=rules(TestFixtures.response(body));
        assertTrue(found.containsAll(Set.of("SENSITIVE-AWS-ACCESS-KEY","SENSITIVE-AWS-SECRET-KEY","SENSITIVE-GITHUB-TOKEN","SENSITIVE-GITLAB-TOKEN","SENSITIVE-JWT","SENSITIVE-PRIVATE-KEY","SENSITIVE-DATABASE-URI","SENSITIVE-GENERIC-SECRET")),found.toString());
    }
    @Test void detectsUrlEncodedAndBase64EncodedSecrets(){
        assertTrue(rules(TestFixtures.response("client_secret%3DD7k%21xP9vQ2mL8zR4")).contains("SENSITIVE-GENERIC-SECRET"));
        String encoded=Base64.getEncoder().encodeToString("client_secret=D7k!xP9vQ2mL8zR4".getBytes(StandardCharsets.UTF_8));
        assertTrue(rules(TestFixtures.response(encoded)).contains("SENSITIVE-GENERIC-SECRET"));
    }
    @Test void rejectsFalsePositiveCorpus(){
        List<String> values=List.of(
            "sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "md5=d41d8cd98f00b204e9800998ecf8427e",
            "id=550e8400-e29b-41d4-a716-446655440000",
            "asset=main.a1b2c3d4e5f67890.js",
            "chunk=abcdef1234567890", "trace_id=0123456789abcdef0123456789abcdef",
            "api_key=YOUR_API_KEY", "client_secret=CHANGE_ME", "data=SGVsbG8gV29ybGQh",
            "order_id=123456789012345678901234567890");
        for(String value:values)assertTrue(rules(TestFixtures.response(value)).isEmpty(),value);
    }
    @Test void deduplicatesFindingsAndCountsOccurrences(){String value="AKIA"+"0".repeat(16);var result=engine.scan(List.of(TestFixtures.response(value+" "+value)),new ScanSettings(),new AtomicBoolean(),(a,b)->{});assertEquals(1,result.findings().size());assertEquals(2,result.findings().get(0).occurrences());}
}
