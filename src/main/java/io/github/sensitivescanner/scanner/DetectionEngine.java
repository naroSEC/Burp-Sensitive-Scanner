package io.github.sensitivescanner.scanner;

import io.github.sensitivescanner.model.Finding;
import io.github.sensitivescanner.model.Location;
import io.github.sensitivescanner.rules.DetectionRule;
import io.github.sensitivescanner.rules.RuleMatch;
import io.github.sensitivescanner.traffic.Fingerprints;
import io.github.sensitivescanner.traffic.TrafficTransaction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

public final class DetectionEngine {
    private final List<DetectionRule> rules;
    private final Normalizer normalizer = new Normalizer();

    public DetectionEngine(List<DetectionRule> rules) {
        this.rules = List.copyOf(rules);
    }

    /** Compatibility entry point used by tests and non-Burp callers. */
    public ScanResult scan(List<TrafficTransaction> input, ScanSettings settings,
                           AtomicBoolean cancelled, BiConsumer<Integer, Integer> progress) {
        ScanSession session = newSession(settings, cancelled);
        int processed = 0;
        for (TrafficTransaction transaction : input) {
            if (cancelled.get()) break;
            session.accept(transaction);
            progress.accept(++processed, input.size());
        }
        return session.finish(input.size(), 0, 0);
    }

    public ScanSession newSession(ScanSettings settings, AtomicBoolean cancelled) {
        return new ScanSession(settings, cancelled);
    }

    /** Stateful, single-threaded scan session. Transactions can be supplied one at a time. */
    public final class ScanSession {
        private final ScanSettings settings;
        private final AtomicBoolean cancelled;
        private final Set<Fingerprints.DigestKey> uniqueTraffic = new HashSet<>();
        private final Map<String, Finding> findings = new LinkedHashMap<>();
        private final Map<Fingerprints.DigestKey, TrafficTransaction> retainedTraffic = new HashMap<>();
        private final Set<Fingerprints.DigestKey> omittedTraffic = new HashSet<>();
        private int scanned;
        private int skippedBinary;
        private int skippedOversized;
        private int errors;
        private int omittedRawMessages;
        private int droppedFindings;
        private long retainedMessageBytes;

        private ScanSession(ScanSettings settings, AtomicBoolean cancelled) {
            this.settings = settings;
            this.cancelled = cancelled;
        }

        public void accept(TrafficTransaction transaction) {
            if (cancelled.get()) return;
            try {
                Fingerprints.DigestKey transactionKey = Fingerprints.transactionKey(transaction);
                if (!uniqueTraffic.add(transactionKey)) return;
                if (transaction.requestLength() > settings.maximumInputSize
                        || transaction.responseLength() > settings.maximumInputSize) {
                    skippedOversized++;
                    return;
                }

                boolean binaryRequest = transaction.requestBodyIsBinary();
                boolean binaryResponse = transaction.responseBodyIsBinary();
                if (binaryRequest || binaryResponse) skippedBinary++;

                List<TextArtifact> artifacts = extract(transaction, binaryRequest, binaryResponse);
                for (TextArtifact raw : artifacts) {
                    if (cancelled.get()) return;
                    for (TextArtifact artifact : normalizer.expand(raw, settings)) {
                        for (DetectionRule rule : rules) {
                            if (settings.disabledRules.contains(rule.id())) continue;
                            for (RuleMatch match : rule.find(artifact, settings)) {
                                addFinding(transaction, transactionKey, artifact, rule, match);
                            }
                        }
                    }
                }
                scanned++;
            } catch (RuntimeException e) {
                errors++;
            }
        }

        private void addFinding(TrafficTransaction transaction,
                                Fingerprints.DigestKey transactionKey,
                                TextArtifact artifact, DetectionRule rule, RuleMatch match) {
            String fingerprint = Fingerprints.finding(
                    rule.id(), transaction.url(), artifact.location().name(), match.value());
            Finding existing = findings.get(fingerprint);
            if (existing != null) {
                existing.increment();
                return;
            }
            if (findings.size() >= settings.maximumFindings) {
                droppedFindings++;
                return;
            }

            TrafficTransaction findingTraffic = trafficForFinding(transactionKey, transaction);
            findings.put(fingerprint, new Finding(
                    fingerprint, rule.id(), rule.category(), rule.name(), rule.description(),
                    rule.severity(), match.confidence(), artifact.location(), match.fieldName(),
                    artifact.path(), SecretUtils.mask(match.value()), Fingerprints.hash(match.value()),
                    findingTraffic));
        }

        private TrafficTransaction trafficForFinding(Fingerprints.DigestKey key,
                                                     TrafficTransaction transaction) {
            TrafficTransaction retained = retainedTraffic.get(key);
            if (retained != null) return retained;

            if (retainedMessageBytes + transaction.messageBytes()
                    <= settings.maximumRetainedFindingBytes) {
                retainedMessageBytes += transaction.messageBytes();
                retainedTraffic.put(key, transaction);
                return transaction;
            }

            TrafficTransaction metadataOnly = transaction.withoutMessages();
            retainedTraffic.put(key, metadataOnly);
            if (omittedTraffic.add(key)) omittedRawMessages++;
            return metadataOnly;
        }

        public int uniqueCount() { return uniqueTraffic.size(); }
        public int scannedCount() { return scanned; }

        public ScanResult finish(int collected, int externallySkippedOversized, int externalErrors) {
            return new ScanResult(
                    collected, uniqueTraffic.size(), scanned, skippedBinary,
                    skippedOversized + externallySkippedOversized, List.copyOf(findings.values()),
                    errors + externalErrors, cancelled.get(), omittedRawMessages, droppedFindings);
        }

        private List<TextArtifact> extract(TrafficTransaction transaction,
                                           boolean binaryRequest, boolean binaryResponse) {
            List<TextArtifact> artifacts = new ArrayList<>();
            if (settings.scanRequest) {
                addMessage(artifacts, transaction.requestText(), true, transaction.url(),
                        false, binaryRequest);
            }
            if (settings.scanResponse) {
                String responseText = transaction.responseText();
                addMessage(artifacts, responseText, false, transaction.url(),
                        isJavaScript(transaction.url(), responseText), binaryResponse);
            }
            return artifacts;
        }

        private void addMessage(List<TextArtifact> output, String raw, boolean request,
                                String url, boolean javascript, boolean skipBody) {
            if (raw.isEmpty()) return;
            int split = headerEnd(raw);
            String headers = split < 0 ? "" : raw.substring(0, split);
            String body = split < 0 ? raw : raw.substring(Math.min(
                    raw.length(), split + (raw.startsWith("\r\n", split) ? 4 : 2)));

            if (request) {
                output.add(new TextArtifact(url, Location.REQUEST_URL, "", "Request URL", 0));
                int query = url.indexOf('?');
                if (query >= 0) {
                    output.add(new TextArtifact(url.substring(query + 1),
                            Location.REQUEST_QUERY, "", "Request Query", 0));
                }
            }

            for (String line : headers.split("\\r?\\n")) {
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                String name = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                Location location = request
                        ? (name.equalsIgnoreCase("Cookie")
                            ? Location.REQUEST_COOKIE : Location.REQUEST_HEADER)
                        : (name.equalsIgnoreCase("Set-Cookie")
                            ? Location.RESPONSE_COOKIE : Location.RESPONSE_HEADER);
                output.add(new TextArtifact(name + ": " + value, location, name,
                        (request ? "Request" : "Response") + " Header " + name, 0));
            }

            if (!skipBody && body.length() <= settings.maximumBodySize && !body.isEmpty()) {
                Location location = request ? Location.REQUEST_BODY
                        : (javascript ? Location.RESPONSE_JAVASCRIPT : Location.RESPONSE_BODY);
                output.add(new TextArtifact(body, location, "",
                        (request ? "Request" : "Response")
                                + (javascript ? " JavaScript" : " Body"), 0));
            }
        }
    }

    private int headerEnd(String value) {
        int position = value.indexOf("\r\n\r\n");
        return position >= 0 ? position : value.indexOf("\n\n");
    }

    private boolean isJavaScript(String url, String responseText) {
        String sample = (url + "\n" + responseText.substring(0, Math.min(2048, responseText.length())))
                .toLowerCase();
        return sample.contains("javascript") || sample.contains("source-map")
                || sample.matches("(?s).*\\.(?:js|map)(?:[?#\\s].*|$)");
    }

    public record ScanResult(
            int collected, int unique, int scanned, int skippedBinary, int skippedOversized,
            List<Finding> findings, int errors, boolean cancelled,
            int omittedRawMessages, int droppedFindings) {}
}
