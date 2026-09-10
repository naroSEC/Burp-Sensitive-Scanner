package io.github.sensitivescanner;

import io.github.sensitivescanner.traffic.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public final class TestFixtures {
    private TestFixtures(){}
    public static TrafficTransaction response(String body){return transaction("GET","https://safe.invalid/api", "GET /api HTTP/1.1\r\nHost: safe.invalid\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"+body);}
    public static TrafficTransaction request(String body){return transaction("POST","https://safe.invalid/api", "POST /api HTTP/1.1\r\nHost: safe.invalid\r\nContent-Type: application/json\r\n\r\n"+body, "HTTP/1.1 204 No Content\r\n\r\n");}
    public static TrafficTransaction transaction(String method,String url,String req,String res){return new TrafficTransaction(Instant.parse("2026-01-01T00:00:00Z"),TrafficSource.LOGGER_CSV,"Test", "safe.invalid",443,true,method,url,req.getBytes(StandardCharsets.ISO_8859_1),res.getBytes(StandardCharsets.ISO_8859_1));}
}
