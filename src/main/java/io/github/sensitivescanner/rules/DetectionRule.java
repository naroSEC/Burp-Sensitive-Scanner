package io.github.sensitivescanner.rules;
import io.github.sensitivescanner.model.Severity;
import io.github.sensitivescanner.scanner.ScanSettings;
import io.github.sensitivescanner.scanner.TextArtifact;
import java.util.List;
import java.util.Set;
import io.github.sensitivescanner.model.ScanArea;
public interface DetectionRule {
    String id(); String name(); String category(); String description(); Severity severity();
    default String regex() { return ""; }
    default Set<ScanArea> areas() { return Set.of(ScanArea.values()); }
    default boolean custom() { return false; }
    List<RuleMatch> find(TextArtifact artifact, ScanSettings settings);
}
