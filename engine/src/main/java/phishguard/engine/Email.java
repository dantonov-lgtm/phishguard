package phishguard.engine;

import java.util.List;
import java.util.Objects;

public record Email(String subject, String body, List<EmailLink> links) {
    public Email {
        subject = Objects.requireNonNull(subject, "subject");
        body = Objects.requireNonNull(body, "body");
        links = List.copyOf(Objects.requireNonNull(links, "links"));
    }
}
