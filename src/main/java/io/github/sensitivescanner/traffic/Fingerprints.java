package io.github.sensitivescanner.traffic;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.nio.ByteBuffer;
import java.util.HexFormat;

public final class Fingerprints {
    private Fingerprints() {}
    public static String transaction(TrafficTransaction tx) {
        return HexFormat.of().formatHex(transactionDigest(tx));
    }
    public static DigestKey transactionKey(TrafficTransaction tx) {
        ByteBuffer value = ByteBuffer.wrap(transactionDigest(tx));
        return new DigestKey(value.getLong(), value.getLong(), value.getLong(), value.getLong());
    }
    private static byte[] transactionDigest(TrafficTransaction tx) {
        MessageDigest md = sha256();
        update(md, tx.method().toUpperCase()); update(md, normalizeUrl(tx.url()));
        update(md, tx.host().toLowerCase()); update(md, Integer.toString(tx.port()));
        md.update((byte)(tx.tls() ? 1 : 0)); md.update(tx.rawRequest()); md.update(tx.rawResponse());
        return md.digest();
    }
    public static String finding(String ruleId, String url, String location, String value) {
        MessageDigest md = sha256();
        update(md, ruleId); update(md, normalizeUrl(url)); update(md, location); update(md, value.trim());
        return HexFormat.of().formatHex(md.digest());
    }
    public static String hash(String value) { MessageDigest md=sha256(); update(md,value); return HexFormat.of().formatHex(md.digest()); }
    public static String normalizeUrl(String value) {
        try {
            URI u = URI.create(value);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
            String host = u.getHost() == null ? "" : u.getHost().toLowerCase();
            int port = u.getPort();
            if ((scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80)) port = -1;
            return new URI(scheme, u.getUserInfo(), host, port, u.getPath(), u.getQuery(), null).toASCIIString();
        } catch (Exception e) { return value == null ? "" : value.trim(); }
    }
    private static MessageDigest sha256() { try { return MessageDigest.getInstance("SHA-256"); } catch(Exception e){ throw new IllegalStateException(e); } }
    private static void update(MessageDigest md, String s) { md.update((s == null ? "" : s).getBytes(StandardCharsets.UTF_8)); md.update((byte)0); }
    public record DigestKey(long first, long second, long third, long fourth) {}
}
