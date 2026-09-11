package io.github.sensitivescanner.model;

import io.github.sensitivescanner.traffic.TrafficTransaction;
import java.time.Instant;

public final class Finding {
    private final String fingerprint, ruleId, category, type, description, fieldName, detectionPath, evidence, valueHash;
    private final Severity severity; private final Confidence confidence; private final Location location;
    private final TrafficTransaction traffic; private final Instant firstSeen; private int occurrences;
    public Finding(String fingerprint,String ruleId,String category,String type,String description,Severity severity,
                   Confidence confidence,Location location,String fieldName,String detectionPath,String evidence,
                   String valueHash,TrafficTransaction traffic) {
        this.fingerprint=fingerprint;this.ruleId=ruleId;this.category=category;this.type=type;this.description=description;
        this.severity=severity;this.confidence=confidence;this.location=location;this.fieldName=fieldName==null?"":fieldName;
        this.detectionPath=detectionPath;this.evidence=evidence;this.valueHash=valueHash;this.traffic=traffic;
        this.firstSeen=traffic.timestamp();this.occurrences=1;
    }
    public void increment(){occurrences++;} public int occurrences(){return occurrences;}
    public String fingerprint(){return fingerprint;} public String ruleId(){return ruleId;} public String category(){return category;}
    public String type(){return type;} public String description(){return description;} public Severity severity(){return severity;}
    public Confidence confidence(){return confidence;} public Location location(){return location;} public String fieldName(){return fieldName;}
    public String detectionPath(){return detectionPath;} public String evidence(){return evidence;} public String valueHash(){return valueHash;}
    public TrafficTransaction traffic(){return traffic;} public Instant firstSeen(){return firstSeen;}
}
