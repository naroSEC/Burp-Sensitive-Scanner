package io.github.sensitivescanner.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.sensitivescanner.model.Finding;
import org.apache.commons.csv.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;

public final class FindingExporter {
    private static final String[] COLUMNS={"timestamp","ruleId","category","type","severity","confidence","host","method","url","location","fieldName","burpTool","trafficSource","maskedEvidence","detectionPath"};
    public void json(Path path,List<Finding> findings)throws IOException{ObjectMapper m=new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);m.writeValue(path.toFile(),findings.stream().map(this::row).toList());}
    public void csv(Path path,List<Finding> findings)throws IOException{try(Writer w=new OutputStreamWriter(new FileOutputStream(path.toFile()),StandardCharsets.UTF_8);CSVPrinter p=new CSVPrinter(w,CSVFormat.RFC4180.builder().setHeader(COLUMNS).get())){for(Finding f:findings){Map<String,Object> r=row(f);p.printRecord(Arrays.stream(COLUMNS).map(r::get).toList());}}}
    private Map<String,Object> row(Finding f){LinkedHashMap<String,Object> r=new LinkedHashMap<>();r.put("timestamp",f.firstSeen().toString());r.put("ruleId",f.ruleId());r.put("category",f.category());r.put("type",f.type());r.put("severity",f.severity());r.put("confidence",f.confidence());r.put("host",f.traffic().host());r.put("method",f.traffic().method());r.put("url",f.traffic().url());r.put("location",f.location());r.put("fieldName",f.fieldName());r.put("burpTool",f.traffic().tool());r.put("trafficSource",f.traffic().source());r.put("maskedEvidence",f.maskedEvidence());r.put("detectionPath",f.detectionPath());return r;}
}
