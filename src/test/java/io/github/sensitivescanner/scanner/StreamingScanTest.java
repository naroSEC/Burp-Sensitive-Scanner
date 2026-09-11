package io.github.sensitivescanner.scanner;

import io.github.sensitivescanner.TestFixtures;
import io.github.sensitivescanner.rules.RuleCatalog;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class StreamingScanTest {
    @Test void parallelScanProducesSameFindingsAsSingleThread() {
        DetectionEngine engine = new DetectionEngine(RuleCatalog.defaults());
        String token = "AKIA" + "0".repeat(16);
        var input = java.util.stream.IntStream.range(0, 200).mapToObj(i -> TestFixtures.transaction(
                "GET", "https://safe.invalid/item/" + i,
                "GET /item/" + i + " HTTP/1.1\r\nHost: safe.invalid\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"" + token + "\",\"index\":" + i + "}")).toList();
        ScanSettings single = new ScanSettings();single.scannerThreads=1;
        ScanSettings parallel = new ScanSettings();parallel.scannerThreads=4;
        var one=engine.scan(input,single,new AtomicBoolean(),(a,b)->{});
        var four=engine.scan(input,parallel,new AtomicBoolean(),(a,b)->{});
        assertEquals(one.scanned(),four.scanned());
        assertEquals(one.findings().stream().map(f->f.fingerprint()).collect(java.util.stream.Collectors.toSet()),four.findings().stream().map(f->f.fingerprint()).collect(java.util.stream.Collectors.toSet()));
    }
    @Test void boundsRawMessagesRetainedByFindings() {
        DetectionEngine engine = new DetectionEngine(RuleCatalog.defaults());
        ScanSettings settings = new ScanSettings();
        settings.maximumRetainedFindingBytes = 1;
        DetectionEngine.ScanSession session = engine.newSession(settings, new AtomicBoolean());

        String token = "AKIA" + "0".repeat(16);
        for (int i = 0; i < 50; i++) {
            session.accept(TestFixtures.transaction(
                    "GET", "https://safe.invalid/item/" + i,
                    "GET /item/" + i + " HTTP/1.1\r\nHost: safe.invalid\r\n\r\n",
                    "HTTP/1.1 200 OK\r\n\r\n" + token));
        }

        DetectionEngine.ScanResult result = session.finish(50, 0, 0);
        assertEquals(50, result.unique());
        assertEquals(50, result.findings().size());
        assertEquals(50, result.omittedRawMessages());
        assertTrue(result.findings().stream().allMatch(f -> f.traffic().messageBytes() == 0));
    }

    @Test void capsFindingCount() {
        DetectionEngine engine = new DetectionEngine(RuleCatalog.defaults());
        ScanSettings settings = new ScanSettings();
        settings.maximumFindings = 10;
        DetectionEngine.ScanSession session = engine.newSession(settings, new AtomicBoolean());
        String token = "AKIA" + "0".repeat(16);
        for (int i = 0; i < 25; i++) {
            session.accept(TestFixtures.transaction("GET", "https://safe.invalid/" + i,
                    "GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n" + token));
        }
        DetectionEngine.ScanResult result = session.finish(25, 0, 0);
        assertEquals(10, result.findings().size());
        assertEquals(15, result.droppedFindings());
    }
}
