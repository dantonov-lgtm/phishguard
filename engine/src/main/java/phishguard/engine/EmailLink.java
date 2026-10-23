package phishguard.engine;

import java.util.Objects;

public record EmailLink(String displayText, String targetUrl) {
    public EmailLink {
        displayText = Objects.requireNonNull(displayText, "displayText");
        targetUrl = Objects.requireNonNull(targetUrl, "targetUrl");
    }
}
