package io.github.sensitivescanner.importer;

import io.github.sensitivescanner.traffic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class LoggerCsvImporterTest {
    @TempDir Path temp;
    @Test void importsRfc4180FeaturesAndContinuesMalformedRows()throws Exception{
        String csv="""
            Tool,URL,Method,Request,Response
            Proxy,https://safe.invalid/a,GET,"GET /a HTTP/1.1
            Host: safe.invalid
            X-Note: ""quoted, value""

            hello","HTTP/1.1 200 OK

            응답"
            Repeater,https://safe.invalid/b,POST,"POST /b HTTP/1.1

            body",
            Bad,https://safe.invalid/c,GET,only-four-columns
            """;
        Path file=temp.resolve("logger.csv");Files.writeString(file,csv,StandardCharsets.UTF_8);TrafficRepository repo=new TrafficRepository(100);
        var r=new LoggerCsvImporter().importFile(file,repo);assertEquals(3,r.totalRows());assertEquals(2,r.imported());assertEquals(1,r.malformed());assertEquals(2,repo.size());assertTrue(repo.snapshot().get(0).requestText().contains("quoted, value"));assertTrue(repo.snapshot().get(0).responseText().contains("응답"));assertEquals(0,repo.snapshot().get(1).response().length);
    }
    @Test void preservesBase64MessageForSafeDecodeDuringAnalysis()throws Exception{
        String raw="HTTP/1.1 200 OK\r\n\r\nclient_secret=D7k!xP9vQ2mL8zR4";String b64=Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
        String csv="Tool,URL,Method,Request,Response\r\nLogger,https://safe.invalid/,GET,\"GET / HTTP/1.1\r\n\r\n\",\""+b64+"\"\r\n";Path file=temp.resolve("base64.csv");Files.writeString(file,csv,StandardCharsets.UTF_8);TrafficRepository repo=new TrafficRepository(100);var r=new LoggerCsvImporter().importFile(file,repo);assertEquals(1,r.imported());assertEquals(b64,repo.snapshot().get(0).responseText());
    }
    @Test void reportsDuplicate()throws Exception{String csv="URL,Request,Response\nhttps://safe.invalid/,\"GET / HTTP/1.1\n\n\",\"\"\nhttps://safe.invalid/,\"GET / HTTP/1.1\n\n\",\"\"\n";Path file=temp.resolve("dupe.csv");Files.writeString(file,csv);TrafficRepository repo=new TrafficRepository(100);var r=new LoggerCsvImporter().importFile(file,repo);assertEquals(1,r.imported());assertEquals(1,r.duplicate());}
}
