package phishguard.engine;

import java.util.Objects;

public record Finding(String id, Severity severity, String description, int points) {
    public Finding {
        id = Objects.requireNonNull(id, "id");
        severity = Objects.requireNonNull(severity, "severity");
        description = Objects.requireNonNull(description, "description");
        if (points < 1 || points > 100) {
            throw new IllegalArgumentException("points must be between 1 and 100");
        }
    }

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH
    }
}
