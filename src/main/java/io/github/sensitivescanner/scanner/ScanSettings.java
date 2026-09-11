package io.github.sensitivescanner.scanner;

import io.github.sensitivescanner.model.Confidence;
import java.util.HashSet;
import java.util.Set;
import java.util.EnumSet;
import java.util.Map;
import java.util.HashMap;
import io.github.sensitivescanner.model.ScanArea;

public final class ScanSettings {
    public int maximumBodySize=2*1024*1024;
    public int maximumInputSize=4*1024*1024;
    public int maximumDecodedSize=2*1024*1024;
    public int maximumDecodeDepth=2;
    public double entropyThreshold=3.5;
    public int maximumFindings=10_000;
    public int maximumEvidenceLength=64*1024;
    public long maximumRetainedFindingBytes=64L*1024*1024;
    public boolean scanRequest=true, scanResponse=true;
    public Confidence minimumConfidence=Confidence.LOW;
    public final Set<String> disabledRules=new HashSet<>();
    public final Set<ScanArea> enabledAreas=EnumSet.allOf(ScanArea.class);
    public final Map<String,Set<ScanArea>> ruleAreas=new HashMap<>();
}
