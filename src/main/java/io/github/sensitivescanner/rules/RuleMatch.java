package io.github.sensitivescanner.rules;
import io.github.sensitivescanner.model.Confidence;
public record RuleMatch(String value,String fieldName,Confidence confidence) {}
