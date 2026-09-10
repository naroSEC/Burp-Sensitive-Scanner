package io.github.sensitivescanner.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import io.github.sensitivescanner.traffic.*;
import java.time.Instant;

final class MontoyaTrafficAdapter {
    private MontoyaTrafficAdapter(){}
    static TrafficTransaction proxy(ProxyHttpRequestResponse m){var r=m.request();var s=r.httpService();return new TrafficTransaction(m.time().toInstant(),TrafficSource.PROXY_HISTORY,"Proxy",s.host(),s.port(),s.secure(),r.method(),r.url(),r.toByteArray().getBytes(),m.hasResponse()?m.response().toByteArray().getBytes():new byte[0]);}
    static TrafficTransaction siteMap(HttpRequestResponse m){var r=m.request();var s=m.httpService();return new TrafficTransaction(Instant.now(),TrafficSource.SITE_MAP,"Target",s.host(),s.port(),s.secure(),r.method(),r.url(),r.toByteArray().getBytes(),m.hasResponse()?m.response().toByteArray().getBytes():new byte[0]);}
}
