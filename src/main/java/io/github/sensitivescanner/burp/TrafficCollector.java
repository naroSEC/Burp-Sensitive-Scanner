package io.github.sensitivescanner.burp;

import burp.api.montoya.MontoyaApi;
import io.github.sensitivescanner.traffic.*;
import java.util.*;

public final class TrafficCollector {
    private final MontoyaApi api;private final TrafficRepository capturedRepository, importedRepository;
    public TrafficCollector(MontoyaApi api,TrafficRepository capturedRepository,TrafficRepository importedRepository){this.api=api;this.capturedRepository=capturedRepository;this.importedRepository=importedRepository;}
    public CollectionResult collect(boolean proxy,boolean siteMap,boolean live,boolean logger,boolean inScopeOnly){
        List<TrafficTransaction> all=new ArrayList<>();int errors=0;
        if(proxy)for(var message:api.proxy().history())try{addIfAllowed(all,MontoyaTrafficAdapter.proxy(message),inScopeOnly);}catch(RuntimeException e){errors++;}
        if(siteMap)for(var message:api.siteMap().requestResponses())try{addIfAllowed(all,MontoyaTrafficAdapter.siteMap(message),inScopeOnly);}catch(RuntimeException e){errors++;}
        if(live)for(TrafficTransaction tx:capturedRepository.snapshot())try{addIfAllowed(all,tx,inScopeOnly);}catch(RuntimeException e){errors++;}
        if(logger)for(TrafficTransaction tx:importedRepository.snapshot())try{addIfAllowed(all,tx,inScopeOnly);}catch(RuntimeException e){errors++;}
        if(errors>0)api.logging().logToError("Traffic collection skipped "+errors+" malformed message(s); HTTP content was not logged.");
        return new CollectionResult(List.copyOf(all),errors);
    }
    private void addIfAllowed(List<TrafficTransaction> out,TrafficTransaction tx,boolean inScopeOnly){if(!inScopeOnly||api.scope().isInScope(tx.url()))out.add(tx);}
    public record CollectionResult(List<TrafficTransaction> traffic,int errors){}
}
