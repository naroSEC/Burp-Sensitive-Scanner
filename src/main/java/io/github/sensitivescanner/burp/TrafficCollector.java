package io.github.sensitivescanner.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import io.github.sensitivescanner.traffic.TrafficRepository;
import io.github.sensitivescanner.traffic.TrafficTransaction;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/** Streams traffic into a consumer so raw messages are never accumulated in a second master list. */
public final class TrafficCollector {
    private final MontoyaApi api;
    private final TrafficRepository capturedRepository;
    private final TrafficRepository importedRepository;

    public TrafficCollector(MontoyaApi api, TrafficRepository capturedRepository,
                            TrafficRepository importedRepository) {
        this.api = api;
        this.capturedRepository = capturedRepository;
        this.importedRepository = importedRepository;
    }

    public CollectionResult stream(boolean proxy, boolean siteMap, boolean live, boolean logger,
                                   boolean inScopeOnly, int maximumMessageBytes,
                                   AtomicBoolean cancelled, Consumer<TrafficTransaction> sink,
                                   BiConsumer<Integer, Integer> progress) {
        MutableStats stats = new MutableStats();
        int repositoryTotal = (live ? capturedRepository.size() : 0)
                + (logger ? importedRepository.size() : 0);
        stats.total = repositoryTotal;

        if (proxy && !cancelled.get()) streamProxy(inScopeOnly, maximumMessageBytes, cancelled, sink, progress, stats);
        if (siteMap && !cancelled.get()) streamSiteMap(inScopeOnly, maximumMessageBytes, cancelled, sink, progress, stats);
        if (live && !cancelled.get()) streamRepository(capturedRepository.snapshot(), inScopeOnly, cancelled, sink, progress, stats);
        if (logger && !cancelled.get()) streamRepository(importedRepository.snapshot(), inScopeOnly, cancelled, sink, progress, stats);

        if (stats.errors > 0) {
            api.logging().logToError("Traffic collection skipped " + stats.errors
                    + " malformed message(s); HTTP content was not logged.");
        }
        return new CollectionResult(stats.collected, stats.skippedOversized, stats.errors);
    }

    private void streamProxy(boolean inScopeOnly, int maximumMessageBytes,
                             AtomicBoolean cancelled, Consumer<TrafficTransaction> sink,
                             BiConsumer<Integer, Integer> progress, MutableStats stats) {
        List<burp.api.montoya.proxy.ProxyHttpRequestResponse> history;
        try {
            history = api.proxy().history();
            stats.total += history.size();
        } catch (RuntimeException e) {
            stats.errors++;
            return;
        }
        for (var message : history) {
            if (cancelled.get()) break;
            try {
                var request = message.request();
                if (!allowed(request.url(), inScopeOnly)) continue;
                stats.collected++;
                if (messageSize(request) > maximumMessageBytes
                        || (message.hasResponse() && messageSize(message.response()) > maximumMessageBytes)) {
                    stats.skippedOversized++;
                    continue;
                }
                ByteArray requestBytes = request.toByteArray();
                ByteArray responseBytes = message.hasResponse() ? message.response().toByteArray() : null;
                sink.accept(MontoyaTrafficAdapter.proxy(message, requestBytes, responseBytes));
            } catch (RuntimeException e) {
                stats.errors++;
            } finally {
                reportProgress(progress, stats);
            }
        }
    }

    private void streamSiteMap(boolean inScopeOnly, int maximumMessageBytes,
                               AtomicBoolean cancelled, Consumer<TrafficTransaction> sink,
                               BiConsumer<Integer, Integer> progress, MutableStats stats) {
        List<burp.api.montoya.http.message.HttpRequestResponse> entries;
        try {
            entries = api.siteMap().requestResponses();
            stats.total += entries.size();
        } catch (RuntimeException e) {
            stats.errors++;
            return;
        }
        for (var message : entries) {
            if (cancelled.get()) break;
            try {
                var request = message.request();
                if (!allowed(request.url(), inScopeOnly)) continue;
                stats.collected++;
                if (messageSize(request) > maximumMessageBytes
                        || (message.hasResponse() && messageSize(message.response()) > maximumMessageBytes)) {
                    stats.skippedOversized++;
                    continue;
                }
                ByteArray requestBytes = request.toByteArray();
                ByteArray responseBytes = message.hasResponse() ? message.response().toByteArray() : null;
                sink.accept(MontoyaTrafficAdapter.siteMap(message, requestBytes, responseBytes));
            } catch (RuntimeException e) {
                stats.errors++;
            } finally {
                reportProgress(progress, stats);
            }
        }
    }

    private void streamRepository(List<TrafficTransaction> entries, boolean inScopeOnly,
                                  AtomicBoolean cancelled, Consumer<TrafficTransaction> sink,
                                  BiConsumer<Integer, Integer> progress, MutableStats stats) {
        for (TrafficTransaction transaction : entries) {
            if (cancelled.get()) break;
            try {
                if (!allowed(transaction.url(), inScopeOnly)) continue;
                stats.collected++;
                sink.accept(transaction);
            } catch (RuntimeException e) {
                stats.errors++;
            } finally {
                reportProgress(progress, stats);
            }
        }
    }

    private boolean allowed(String url, boolean inScopeOnly) {
        return !inScopeOnly || api.scope().isInScope(url);
    }

    private long messageSize(burp.api.montoya.http.message.HttpMessage message) {
        return (long) message.bodyOffset() + message.body().length();
    }

    private void reportProgress(BiConsumer<Integer, Integer> progress, MutableStats stats) {
        stats.processed++;
        progress.accept(stats.processed, Math.max(stats.processed, stats.total));
    }

    private static final class MutableStats {
        int collected;
        int skippedOversized;
        int errors;
        int processed;
        int total;
    }

    public record CollectionResult(int collected, int skippedOversized, int errors) {}
}
