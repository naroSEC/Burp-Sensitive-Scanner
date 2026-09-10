package io.github.sensitivescanner.traffic;

import java.util.*;

public final class TrafficRepository {
    private final LinkedHashMap<String, TrafficTransaction> entries = new LinkedHashMap<>();
    private int maxEntries;
    private long evicted;
    public TrafficRepository(int maxEntries) { this.maxEntries = Math.max(100, maxEntries); }
    public synchronized boolean add(TrafficTransaction tx) {
        String fp = Fingerprints.transaction(tx);
        if (entries.containsKey(fp)) return false;
        entries.put(fp, tx);
        while (entries.size() > maxEntries) { entries.remove(entries.keySet().iterator().next()); evicted++; }
        return true;
    }
    public synchronized AddResult addAll(Collection<TrafficTransaction> values) {
        int added=0, duplicate=0; for (TrafficTransaction t:values) { if(add(t)) added++; else duplicate++; }
        return new AddResult(added, duplicate);
    }
    public synchronized List<TrafficTransaction> snapshot() { return List.copyOf(entries.values()); }
    public synchronized int size() { return entries.size(); }
    public synchronized long evicted() { return evicted; }
    public synchronized void clear() { entries.clear(); evicted=0; }
    public synchronized void setMaxEntries(int value) { maxEntries=Math.max(100,value); }
    public record AddResult(int added, int duplicate) {}
}
