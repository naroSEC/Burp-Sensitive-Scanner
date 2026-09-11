package io.github.sensitivescanner.scanner;

import io.github.sensitivescanner.model.Confidence;
import java.util.HashSet;
import java.util.Set;

public final class ScanSettings {
    public int maximumBodySize=2*1024*1024;
    public int maximumInputSize=4*1024*1024;
    public int maximumDecodedSize=2*1024*1024;
    public int maximumDecodeDepth=2;
    public double entropyThreshold=3.5;
    public int maximumFindings=10_000;
    public long maximumRetainedFindingBytes=64L*1024*1024;
    public boolean scanRequest=true, scanResponse=true;
    public Confidence minimumConfidence=Confidence.LOW;
    public final Set<String> disabledRules=new HashSet<>();
}
