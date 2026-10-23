package phishguard.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class PhishingScanner {
    private final List<Heuristic> heuristics;

    public PhishingScanner() {
        this(List.of(new UrgencyHeuristic(), new CredentialRequestHeuristic(), new LinkHeuristic()));
    }

    public PhishingScanner(List<Heuristic> heuristics) {
        this.heuristics = List.copyOf(Objects.requireNonNull(heuristics, "heuristics"));
    }

    public ScanResult scan(Email email) {
        Objects.requireNonNull(email, "email");
        Map<String, Finding> findingsById = new LinkedHashMap<>();
        for (Heuristic heuristic : heuristics) {
            for (Finding finding : heuristic.analyze(email)) {
                findingsById.putIfAbsent(finding.id(), finding);
            }
        }

        List<Finding> findings = new ArrayList<>(findingsById.values());
        int score = Math.min(100, findings.stream().mapToInt(Finding::points).sum());
        ScanResult.Risk risk = score >= 50
                ? ScanResult.Risk.HIGH
                : score >= 20 ? ScanResult.Risk.MEDIUM : ScanResult.Risk.LOW;
        String guidance = switch (risk) {
            case HIGH -> "Do not open links or attachments. Verify the sender through a separate, trusted channel.";
            case MEDIUM -> "Use caution. Verify unexpected requests and inspect links before interacting.";
            case LOW -> "No obvious warning signs were detected. This is not proof that the message is safe.";
        };
        return new ScanResult(risk, score, findings, guidance);
    }
}
