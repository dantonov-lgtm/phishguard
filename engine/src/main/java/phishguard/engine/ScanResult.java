package phishguard.engine;

import java.util.List;
import java.util.Objects;

public record ScanResult(Risk risk, int score, List<Finding> findings, String guidance) {
    public ScanResult {
        risk = Objects.requireNonNull(risk, "risk");
        findings = List.copyOf(Objects.requireNonNull(findings, "findings"));
        guidance = Objects.requireNonNull(guidance, "guidance");
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("score must be between 0 and 100");
        }
    }

    public enum Risk {
        LOW,
        MEDIUM,
        HIGH
    }
}
