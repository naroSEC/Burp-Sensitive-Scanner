package io.github.sensitivescanner.traffic;

import java.util.*;

public final class TrafficRepository {
    private final LinkedHashMap<Fingerprints.DigestKey, TrafficTransaction> entries = new LinkedHashMap<>();
    private int maxEntries;
    private long maxBytes;
    private long storedBytes;
    private long evicted;
    public TrafficRepository(int maxEntries) { this(maxEntries, 256L * 1024 * 1024); }
    public TrafficRepository(int maxEntries, long maxBytes) { this.maxEntries = Math.max(100, maxEntries); this.maxBytes = Math.max(1024, maxBytes); }
    public synchronized boolean add(TrafficTransaction tx) {
        Fingerprints.DigestKey fp = Fingerprints.transactionKey(tx);
        if (entries.containsKey(fp)) return false;
        entries.put(fp, tx);
        storedBytes += tx.messageBytes();
        evictToLimits();
        return true;
    }
    public synchronized AddResult addAll(Collection<TrafficTransaction> values) {
        int added=0, duplicate=0; for (TrafficTransaction t:values) { if(add(t)) added++; else duplicate++; }
        return new AddResult(added, duplicate);
    }
    public synchronized List<TrafficTransaction> snapshot() { return List.copyOf(entries.values()); }
    public synchronized int size() { return entries.size(); }
    public synchronized long storedBytes() { return storedBytes; }
    public synchronized long evicted() { return evicted; }
    public synchronized void clear() { entries.clear(); storedBytes=0; evicted=0; }
    public synchronized void setMaxEntries(int value) { maxEntries=Math.max(100,value); evictToLimits(); }
    public synchronized void setMaxBytes(long value) { maxBytes=Math.max(1024,value); evictToLimits(); }
    private void evictToLimits() { while (entries.size() > maxEntries || storedBytes > maxBytes) { var iterator=entries.entrySet().iterator(); if(!iterator.hasNext())break; var oldest=iterator.next(); storedBytes-=oldest.getValue().messageBytes(); iterator.remove(); evicted++; } }
    public record AddResult(int added, int duplicate) {}
}
