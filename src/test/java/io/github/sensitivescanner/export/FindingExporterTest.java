package io.github.sensitivescanner.export;

import io.github.sensitivescanner.TestFixtures;
import io.github.sensitivescanner.rules.RuleCatalog;
import io.github.sensitivescanner.scanner.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class FindingExporterTest {
    @TempDir Path directory;
    @Test void exportsUnmaskedMatch() throws Exception {
        String token="AKIA"+"0".repeat(16);
        var result=new DetectionEngine(RuleCatalog.defaults()).scan(List.of(TestFixtures.response(token)),new ScanSettings(),new AtomicBoolean(),(a,b)->{});
        Path csv=directory.resolve("findings.csv");new FindingExporter().csv(csv,result.findings());String content=Files.readString(csv);
        assertTrue(content.contains("match"));assertTrue(content.contains(token));assertFalse(content.contains("maskedEvidence"));
    }
}
