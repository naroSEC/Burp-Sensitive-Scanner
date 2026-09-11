package io.github.sensitivescanner.rules;

import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.scanner.*;
import java.util.*;
import java.util.function.BiFunction;
import java.util.regex.*;

public final class RegexRule implements DetectionRule {
    private final String id,name,category,description,regex; private final Severity severity; private final Pattern pattern;
    private final Set<ScanArea> areas; private final int matchGroup;
    private final BiFunction<String,ScanSettings,Confidence> confidence;
    public RegexRule(String id,String name,String category,String description,Severity severity,String regex,int flags,BiFunction<String,ScanSettings,Confidence> confidence){this(id,name,category,description,severity,regex,flags,confidence,Set.of(ScanArea.values()));}
    public RegexRule(String id,String name,String category,String description,Severity severity,String regex,int flags,BiFunction<String,ScanSettings,Confidence> confidence,Set<ScanArea> areas){this(id,name,category,description,severity,regex,flags,confidence,areas,-1);}
    public RegexRule(String id,String name,String category,String description,Severity severity,String regex,int flags,BiFunction<String,ScanSettings,Confidence> confidence,Set<ScanArea> areas,int matchGroup){this.id=id;this.name=name;this.category=category;this.description=description;this.severity=severity;this.regex=regex;this.pattern=Pattern.compile(regex,flags);this.confidence=confidence;this.areas=Set.copyOf(areas);this.matchGroup=matchGroup;}
    public String id(){return id;}public String name(){return name;}public String category(){return category;}public String description(){return description;}public Severity severity(){return severity;}public String regex(){return regex;}public Set<ScanArea> areas(){return areas;}
    public List<RuleMatch> find(TextArtifact a,ScanSettings s){List<RuleMatch> out=null;Matcher m=pattern.matcher(a.text());while(m.find()){String v=matchedValue(m);if(v==null||SecretUtils.placeholder(v))continue;Confidence c=confidence.apply(v,s);if(c!=null&&c.meets(s.minimumConfidence)){if(out==null)out=new ArrayList<>();out.add(new RuleMatch(v,a.fieldName(),c));}}return out==null?List.of():out;}
    private String matchedValue(Matcher matcher){if(matcher.groupCount()==0)return matcher.group();if(matchGroup>0)return matcher.group(matchGroup);if(matchGroup==0){for(int i=1;i<=matcher.groupCount();i++){String value=matcher.group(i);if(value!=null)return value;}return null;}return matcher.group(matcher.groupCount());}
}
