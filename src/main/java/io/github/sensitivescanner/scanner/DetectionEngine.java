package io.github.sensitivescanner.scanner;

import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.rules.*;
import io.github.sensitivescanner.traffic.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.regex.*;

public final class DetectionEngine {
    private final List<DetectionRule> rules; private final Normalizer normalizer=new Normalizer();
    public DetectionEngine(List<DetectionRule> rules){this.rules=List.copyOf(rules);}
    public ScanResult scan(List<TrafficTransaction> input,ScanSettings settings,AtomicBoolean cancelled,BiConsumer<Integer,Integer> progress){
        LinkedHashMap<String,TrafficTransaction> unique=new LinkedHashMap<>();for(var t:input)unique.putIfAbsent(Fingerprints.transaction(t),t);
        LinkedHashMap<String,Finding> findings=new LinkedHashMap<>();int scanned=0,binary=0,oversized=0,errors=0,processed=0,total=unique.size();
        for(TrafficTransaction tx:unique.values()){
            if(cancelled.get())break;
            try{
                if((tx.request().length>settings.maximumInputSize)||(tx.response().length>settings.maximumInputSize)){oversized++;processed++;progress.accept(processed,total);continue;}
                boolean binaryRequest=isBinaryBody(tx.request()),binaryResponse=isBinaryBody(tx.response());if(binaryRequest||binaryResponse)binary++;
                List<TextArtifact> artifacts=extract(tx,settings,binaryRequest,binaryResponse);
                for(TextArtifact raw:artifacts)for(TextArtifact a:normalizer.expand(raw,settings))for(DetectionRule rule:rules){
                    if(settings.disabledRules.contains(rule.id()))continue;
                    for(RuleMatch match:rule.find(a,settings)){
                        String fp=Fingerprints.finding(rule.id(),tx.url(),a.location().name(),match.value()); Finding existing=findings.get(fp);
                        if(existing!=null){existing.increment();continue;}
                        findings.put(fp,new Finding(fp,rule.id(),rule.category(),rule.name(),rule.description(),rule.severity(),match.confidence(),a.location(),match.fieldName(),a.path(),SecretUtils.mask(match.value()),Fingerprints.hash(match.value()),tx));
                    }
                } scanned++;
            }catch(RuntimeException e){errors++;}
            processed++;progress.accept(processed,total);
        }
        return new ScanResult(input.size(),unique.size(),scanned,binary,oversized,List.copyOf(findings.values()),errors,cancelled.get());
    }
    private List<TextArtifact> extract(TrafficTransaction tx,ScanSettings s,boolean binaryRequest,boolean binaryResponse){List<TextArtifact> a=new ArrayList<>();if(s.scanRequest)addMessage(a,tx.requestText(),true,tx.url(),false,binaryRequest,s);if(s.scanResponse)addMessage(a,tx.responseText(),false,tx.url(),isJavaScript(tx),binaryResponse,s);return a;}
    private void addMessage(List<TextArtifact> out,String raw,boolean request,String url,boolean js,boolean skipBody,ScanSettings s){if(raw.isEmpty())return;int split=headerEnd(raw);String headers=split<0?"":raw.substring(0,split);String body=split<0?raw:raw.substring(Math.min(raw.length(),split+(raw.startsWith("\r\n",split)?4:2)));if(request){out.add(new TextArtifact(url,Location.REQUEST_URL,"","Request URL",0));int q=url.indexOf('?');if(q>=0)out.add(new TextArtifact(url.substring(q+1),Location.REQUEST_QUERY,"","Request Query",0));}for(String line:headers.split("\\r?\\n")){int c=line.indexOf(':');if(c<=0)continue;String name=line.substring(0,c).trim(),value=line.substring(c+1).trim();Location loc=request?(name.equalsIgnoreCase("Cookie")?Location.REQUEST_COOKIE:Location.REQUEST_HEADER):(name.equalsIgnoreCase("Set-Cookie")?Location.RESPONSE_COOKIE:Location.RESPONSE_HEADER);out.add(new TextArtifact(name+": "+value,loc,name,(request?"Request":"Response")+" Header "+name,0));}if(!skipBody&&body.length()<=s.maximumBodySize&&!body.isEmpty()){Location loc=request?Location.REQUEST_BODY:(js?Location.RESPONSE_JAVASCRIPT:Location.RESPONSE_BODY);out.add(new TextArtifact(body,loc,"",(request?"Request":"Response")+(js?" JavaScript":" Body"),0));}}
    private int headerEnd(String s){int p=s.indexOf("\r\n\r\n");return p>=0?p:s.indexOf("\n\n");}
    private boolean isJavaScript(TrafficTransaction tx){String l=(tx.url()+"\n"+tx.responseText().substring(0,Math.min(2048,tx.responseText().length()))).toLowerCase();return l.contains("javascript")||l.contains("source-map")||l.matches("(?s).*\\.(?:js|map)(?:[?#\\s].*|$)");}
    private boolean isBinaryBody(byte[] b){if(b.length==0)return false;int start=bodyOffset(b),n=Math.min(b.length,start+4096),bad=0,count=n-start;if(count<=0)return false;for(int i=start;i<n;i++){int v=b[i]&255;if(v==0||(v<9)||(v>13&&v<32))bad++;}return bad>count/10;}
    private int bodyOffset(byte[] b){for(int i=0;i+3<b.length;i++)if(b[i]==13&&b[i+1]==10&&b[i+2]==13&&b[i+3]==10)return i+4;for(int i=0;i+1<b.length;i++)if(b[i]==10&&b[i+1]==10)return i+2;return 0;}
    public record ScanResult(int collected,int unique,int scanned,int skippedBinary,int skippedOversized,List<Finding> findings,int errors,boolean cancelled){}
}
