package io.github.sensitivescanner.traffic;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

public record TrafficTransaction(
        Instant timestamp, TrafficSource source, String tool, String host, int port,
        boolean tls, String method, String url, byte[] request, byte[] response) {
    public TrafficTransaction {
        timestamp = timestamp == null ? Instant.now() : timestamp;
        source = source == null ? TrafficSource.LIVE_CAPTURE : source;
        tool = clean(tool); host = clean(host); method = clean(method); url = clean(url);
        request = request == null ? new byte[0] : Arrays.copyOf(request, request.length);
        response = response == null ? new byte[0] : Arrays.copyOf(response, response.length);
    }
    private static String clean(String s) { return s == null ? "" : s; }
    @Override public byte[] request() { return Arrays.copyOf(request, request.length); }
    @Override public byte[] response() { return Arrays.copyOf(response, response.length); }
    public String requestText() { return new String(request, StandardCharsets.UTF_8); }
    public String responseText() { return new String(response, StandardCharsets.UTF_8); }
}
