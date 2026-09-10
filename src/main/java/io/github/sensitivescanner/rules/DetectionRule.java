package io.github.sensitivescanner.rules;
import io.github.sensitivescanner.model.Severity;
import io.github.sensitivescanner.scanner.ScanSettings;
import io.github.sensitivescanner.scanner.TextArtifact;
import java.util.List;
public interface DetectionRule {
    String id(); String name(); String category(); String description(); Severity severity();
    List<RuleMatch> find(TextArtifact artifact, ScanSettings settings);
}
