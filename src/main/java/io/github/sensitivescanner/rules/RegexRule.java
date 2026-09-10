package io.github.sensitivescanner.rules;

import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.scanner.*;
import java.util.*;
import java.util.function.BiFunction;
import java.util.regex.*;

public final class RegexRule implements DetectionRule {
    private final String id,name,category,description; private final Severity severity; private final Pattern pattern;
    private final BiFunction<String,ScanSettings,Confidence> confidence;
    public RegexRule(String id,String name,String category,String description,Severity severity,String regex,int flags,BiFunction<String,ScanSettings,Confidence> confidence){this.id=id;this.name=name;this.category=category;this.description=description;this.severity=severity;this.pattern=Pattern.compile(regex,flags);this.confidence=confidence;}
    public String id(){return id;}public String name(){return name;}public String category(){return category;}public String description(){return description;}public Severity severity(){return severity;}
    public List<RuleMatch> find(TextArtifact a,ScanSettings s){List<RuleMatch> out=new ArrayList<>();Matcher m=pattern.matcher(a.text());while(m.find()){String v=m.group(m.groupCount()>0?m.groupCount():0);if(v==null||SecretUtils.placeholder(v))continue;Confidence c=confidence.apply(v,s);if(c!=null&&c.meets(s.minimumConfidence))out.add(new RuleMatch(v,a.fieldName(),c));}return out;}
}
