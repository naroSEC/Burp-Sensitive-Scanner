package io.github.sensitivescanner.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import io.github.sensitivescanner.traffic.TrafficSource;
import io.github.sensitivescanner.traffic.TrafficTransaction;

import java.time.Instant;

final class MontoyaTrafficAdapter {
    private MontoyaTrafficAdapter() {}

    static TrafficTransaction proxy(ProxyHttpRequestResponse message,
                                    ByteArray requestBytes, ByteArray responseBytes) {
        var request = message.request();
        var service = request.httpService();
        return TrafficTransaction.fromOwnedBytes(
                message.time().toInstant(), TrafficSource.PROXY_HISTORY, "Proxy",
                service.host(), service.port(), service.secure(), request.method(), request.url(),
                requestBytes.getBytes(), responseBytes == null ? new byte[0] : responseBytes.getBytes());
    }

    static TrafficTransaction siteMap(HttpRequestResponse message,
                                      ByteArray requestBytes, ByteArray responseBytes) {
        var request = message.request();
        var service = message.httpService();
        return TrafficTransaction.fromOwnedBytes(
                Instant.now(), TrafficSource.SITE_MAP, "Target",
                service.host(), service.port(), service.secure(), request.method(), request.url(),
                requestBytes.getBytes(), responseBytes == null ? new byte[0] : responseBytes.getBytes());
    }
}
