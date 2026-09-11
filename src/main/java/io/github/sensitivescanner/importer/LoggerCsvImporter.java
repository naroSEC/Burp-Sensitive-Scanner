package io.github.sensitivescanner.importer;

import io.github.sensitivescanner.traffic.*;
import org.apache.commons.csv.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.time.format.DateTimeParseException;
import java.util.*;

public final class LoggerCsvImporter {
    public ImportResult importFile(Path path, TrafficRepository repository) {
        int total=0, imported=0, skipped=0, malformed=0, duplicate=0;List<String> errors=new ArrayList<>();
        try(Reader reader=new InputStreamReader(new FileInputStream(path.toFile()),StandardCharsets.UTF_8);
            CSVParser parser=CSVFormat.RFC4180.builder().setHeader().setSkipHeaderRecord(true).setIgnoreEmptyLines(false).get().parse(reader)) {
            Map<String,String> headers=normalizedHeaders(parser.getHeaderMap().keySet());
            for(CSVRecord row:parser){total++;try{
                String request=value(row,headers,"request","http request","request raw","requestraw");
                String response=value(row,headers,"response","http response","response raw","responseraw");
                if(request.isEmpty())request=valueStartingWith(row,headers,"request");
                if(response.isEmpty())response=valueStartingWith(row,headers,"response");
                String url=value(row,headers,"url","request url","requesturl");
                if(request.isBlank()&&response.isBlank()){skipped++;continue;}
                if(row.size()!=parser.getHeaderMap().size()){malformed++;continue;}
                url=stripExcelPrefix(url);
                URI uri=parseUri(url);String host=first(value(row,headers,"host","hostname"),uri==null?"":uri.getHost());
                boolean tls=parseTls(value(row,headers,"tls","secure","protocol","scheme"),uri);int port=parsePort(value(row,headers,"port"),uri,tls);
                String method=first(value(row,headers,"method","http method","request method"),methodFromRequest(request));
                String tool=first(value(row,headers,"tool","burp tool","source tool"),"Logger");
                Instant time=parseTime(value(row,headers,"time","timestamp","date"));
                TrafficTransaction tx=TrafficTransaction.fromOwnedBytes(time,TrafficSource.LOGGER_CSV,tool,host,port,tls,method,url,request.getBytes(StandardCharsets.UTF_8),response.getBytes(StandardCharsets.UTF_8));
                if(repository.add(tx))imported++;else duplicate++;
            }catch(RuntimeException e){malformed++;if(errors.size()<20)errors.add("Row "+row.getRecordNumber()+": "+safeMessage(e));}}
        }catch(Exception e){errors.add("CSV parse error: "+safeMessage(e));}
        return new ImportResult(total,imported,skipped,malformed,duplicate,List.copyOf(errors));
    }
    private Map<String,String> normalizedHeaders(Set<String> names){Map<String,String> out=new HashMap<>();for(String n:names)out.put(normalize(n),n);return out;}
    private String value(CSVRecord r,Map<String,String> h,String...aliases){for(String a:aliases){String actual=h.get(normalize(a));if(actual!=null&&r.isMapped(actual)&&r.isSet(actual)){String v=r.get(actual);if(v!=null&&!v.isEmpty())return v;}}return "";}
    private String valueStartingWith(CSVRecord r,Map<String,String> h,String prefix){String p=normalize(prefix);for(var e:h.entrySet())if(e.getKey().startsWith(p)&&r.isMapped(e.getValue())&&r.isSet(e.getValue()))return r.get(e.getValue());return "";}
    private String normalize(String s){return s==null?"":s.replace("\uFEFF","").toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]","");}
    private String stripExcelPrefix(String s){return s.startsWith("'")?s.substring(1):s;}
    private String first(String a,String b){return a==null||a.isBlank()?b:a;}
    private URI parseUri(String s){try{return s.isBlank()?null:URI.create(s);}catch(Exception e){return null;}}
    private boolean parseTls(String s,URI u){if(u!=null&&"https".equalsIgnoreCase(u.getScheme()))return true;String n=s.toLowerCase(Locale.ROOT);return n.equals("true")||n.equals("yes")||n.equals("https")||n.equals("tls");}
    private int parsePort(String s,URI u,boolean tls){try{return Integer.parseInt(s);}catch(Exception ignored){}if(u!=null&&u.getPort()>0)return u.getPort();return tls?443:80;}
    private String methodFromRequest(String s){String n=stripExcelPrefix(s);int p=n.indexOf(' ');return p>0&&p<20?n.substring(0,p):"";}
    private Instant parseTime(String s){if(s.isBlank())return Instant.now();try{return Instant.parse(s);}catch(DateTimeParseException ignored){}try{return ZonedDateTime.parse(s).toInstant();}catch(DateTimeParseException ignored){return Instant.now();}}
    private String safeMessage(Throwable e){String m=e.getMessage();return m==null?e.getClass().getSimpleName():m.replaceAll("[\\r\\n]+"," ");}
    public record ImportResult(int totalRows,int imported,int skipped,int malformed,int duplicate,List<String> errors){}
}
