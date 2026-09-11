package io.github.sensitivescanner.burp;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;
import io.github.sensitivescanner.traffic.*;
import java.time.Instant;

final class LiveTrafficCollector implements HttpHandler {
    private final TrafficRepository repository;private final Logging logging;
    LiveTrafficCollector(TrafficRepository repository,Logging logging){this.repository=repository;this.logging=logging;}
    @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request){return RequestToBeSentAction.continueWith(request);}
    @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response){
        try{var req=response.initiatingRequest();var svc=req.httpService();repository.add(TrafficTransaction.fromOwnedBytes(Instant.now(),TrafficSource.LIVE_CAPTURE,response.toolSource().toolType().toolName(),svc.host(),svc.port(),svc.secure(),req.method(),req.url(),req.toByteArray().getBytes(),response.toByteArray().getBytes()));}catch(RuntimeException e){logging.logToError("Live traffic capture failed ("+e.getClass().getSimpleName()+"); HTTP content was not logged.");}
        return ResponseReceivedAction.continueWith(response);
    }
}
