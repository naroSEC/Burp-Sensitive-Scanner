package io.github.sensitivescanner.rules;

import io.github.sensitivescanner.model.*;
import io.github.sensitivescanner.scanner.*;
import java.util.*;
import java.util.regex.*;

public final class CustomRegexRule implements DetectionRule {
    private final String id, name, regex, description;
    private final Severity severity;
    private final Set<ScanArea> areas;
    private final Pattern pattern;

    public CustomRegexRule(String id, String name, String regex, String description,
                           Severity severity, Set<ScanArea> areas) {
        this.id = Objects.requireNonNull(id);
        this.name = require(name, "Rule name");
        this.regex = require(regex, "Regular expression");
        this.description = description == null ? "" : description.trim();
        this.severity = Objects.requireNonNull(severity);
        if (areas == null || areas.isEmpty()) throw new IllegalArgumentException("Select at least one scan area");
        this.areas = Set.copyOf(areas);
        this.pattern = Pattern.compile(regex, Pattern.MULTILINE);
    }

    private static String require(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(label + " is required");
        return value.trim();
    }

    public String id(){return id;} public String name(){return name;}
    public String category(){return "Custom";} public String description(){return description;}
    public Severity severity(){return severity;} public String regex(){return regex;}
    public Set<ScanArea> areas(){return areas;} public boolean custom(){return true;}

    public List<RuleMatch> find(TextArtifact artifact, ScanSettings settings) {
        List<RuleMatch> matches = null;
        Matcher matcher = pattern.matcher(artifact.text());
        while (matcher.find()) {
            String value = matcher.group();
            if (!value.isEmpty()) { if (matches == null) matches = new ArrayList<>(); matches.add(new RuleMatch(value, artifact.fieldName(), Confidence.HIGH)); }
        }
        return matches == null ? List.of() : matches;
    }
}
