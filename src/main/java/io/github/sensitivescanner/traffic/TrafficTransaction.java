package io.github.sensitivescanner.traffic;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;

/** Immutable transaction metadata with owned request and response byte arrays. */
public final class TrafficTransaction {
    private static final byte[] EMPTY = new byte[0];

    private final Instant timestamp;
    private final TrafficSource source;
    private final String tool;
    private final String host;
    private final int port;
    private final boolean tls;
    private final String method;
    private final String url;
    private final byte[] request;
    private final byte[] response;

    /** Copies caller-owned arrays. Use {@link #fromOwnedBytes} for newly allocated arrays. */
    public TrafficTransaction(Instant timestamp, TrafficSource source, String tool, String host,
                              int port, boolean tls, String method, String url,
                              byte[] request, byte[] response) {
        this(timestamp, source, tool, host, port, tls, method, url, request, response, false);
    }

    private TrafficTransaction(Instant timestamp, TrafficSource source, String tool, String host,
                               int port, boolean tls, String method, String url,
                               byte[] request, byte[] response, boolean takeOwnership) {
        this.timestamp = timestamp == null ? Instant.now() : timestamp;
        this.source = source == null ? TrafficSource.LIVE_CAPTURE : source;
        this.tool = clean(tool);
        this.host = clean(host);
        this.port = port;
        this.tls = tls;
        this.method = clean(method);
        this.url = clean(url);
        this.request = store(request, takeOwnership);
        this.response = store(response, takeOwnership);
    }

    /** Avoids a second full-size copy when the byte arrays were just created for this object. */
    public static TrafficTransaction fromOwnedBytes(Instant timestamp, TrafficSource source,
                                                     String tool, String host, int port, boolean tls,
                                                     String method, String url,
                                                     byte[] request, byte[] response) {
        return new TrafficTransaction(timestamp, source, tool, host, port, tls, method, url,
                request, response, true);
    }

    public TrafficTransaction withoutMessages() {
        return fromOwnedBytes(timestamp, source, tool, host, port, tls, method, url, EMPTY, EMPTY);
    }

    public Instant timestamp() { return timestamp; }
    public TrafficSource source() { return source; }
    public String tool() { return tool; }
    public String host() { return host; }
    public int port() { return port; }
    public boolean tls() { return tls; }
    public String method() { return method; }
    public String url() { return url; }
    public int requestLength() { return request.length; }
    public int responseLength() { return response.length; }
    public long messageBytes() { return (long) request.length + response.length; }
    public byte[] request() { return Arrays.copyOf(request, request.length); }
    public byte[] response() { return Arrays.copyOf(response, response.length); }
    public String requestText() { return new String(request, StandardCharsets.UTF_8); }
    public String responseText() { return new String(response, StandardCharsets.UTF_8); }
    public boolean requestBodyIsBinary() { return bodyIsBinary(request); }
    public boolean responseBodyIsBinary() { return bodyIsBinary(response); }

    byte[] rawRequest() { return request; }
    byte[] rawResponse() { return response; }

    private static byte[] store(byte[] value, boolean takeOwnership) {
        if (value == null || value.length == 0) return EMPTY;
        return takeOwnership ? value : Arrays.copyOf(value, value.length);
    }

    private static String clean(String value) { return value == null ? "" : value; }

    private static boolean bodyIsBinary(byte[] bytes) {
        if (bytes.length == 0) return false;
        int start = bodyOffset(bytes);
        int end = Math.min(bytes.length, start + 4096);
        int count = end - start;
        if (count <= 0) return false;
        int bad = 0;
        for (int i = start; i < end; i++) {
            int value = bytes[i] & 0xff;
            if (value == 0 || value < 9 || (value > 13 && value < 32)) bad++;
        }
        return bad > count / 10;
    }

    private static int bodyOffset(byte[] bytes) {
        for (int i = 0; i + 3 < bytes.length; i++) {
            if (bytes[i] == 13 && bytes[i + 1] == 10 && bytes[i + 2] == 13 && bytes[i + 3] == 10) {
                return i + 4;
            }
        }
        for (int i = 0; i + 1 < bytes.length; i++) {
            if (bytes[i] == 10 && bytes[i + 1] == 10) return i + 2;
        }
        return 0;
    }
}
