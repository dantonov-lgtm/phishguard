package phishguard.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import phishguard.engine.Email;
import phishguard.engine.EmailLink;
import phishguard.engine.PhishingScanner;

public final class Main {
    private static final int MAX_REQUEST_BYTES = 64 * 1024;
    private static final int MAX_LINKS = 50;

    private Main() {
    }

    public static void main(String[] args) {
        String extensionOrigin = System.getenv("PHISHGUARD_EXTENSION_ORIGIN");
        ObjectMapper mapper = new ObjectMapper();
        PhishingScanner scanner = new PhishingScanner();

        Javalin app = Javalin.create(config -> config.showJavalinBanner = false);
        app.before(ctx -> {
            String origin = ctx.header("Origin");
            if (origin != null) {
                if (!origin.equals(extensionOrigin)) {
                    ctx.status(403).json(Map.of("error", "Origin is not allowed."));
                    ctx.skipRemainingHandlers();
                    return;
                }
                ctx.header("Access-Control-Allow-Origin", origin);
                ctx.header("Vary", "Origin");
                ctx.header("Access-Control-Allow-Methods", "POST, OPTIONS");
                ctx.header("Access-Control-Allow-Headers", "Content-Type");
            }
        });
        app.options("/api/scan", ctx -> ctx.status(204));
        app.post("/api/scan", ctx -> {
            String body = ctx.body();
            if (body.getBytes(StandardCharsets.UTF_8).length > MAX_REQUEST_BYTES) {
                ctx.status(413).json(Map.of("error", "Request is too large."));
                return;
            }
            ScanRequest request;
            try {
                request = mapper.readValue(body, ScanRequest.class);
            } catch (JsonProcessingException exception) {
                ctx.status(400).json(Map.of("error", "Request must be valid JSON."));
                return;
            }
            if (request == null || request.body() == null || request.body().isBlank()) {
                ctx.status(400).json(Map.of("error", "Email body is required."));
                return;
            }
            List<LinkRequest> requestLinks = request.links() == null ? List.of() : request.links();
            if (requestLinks.size() > MAX_LINKS) {
                ctx.status(400).json(Map.of("error", "A maximum of 50 links can be scanned."));
                return;
            }
            if (requestLinks.stream().anyMatch(link ->
                    link == null || link.displayText() == null || link.targetUrl() == null)) {
                ctx.status(400).json(Map.of("error", "Each link requires displayText and targetUrl."));
                return;
            }
            List<EmailLink> links = requestLinks.stream()
                    .map(link -> new EmailLink(
                            link.displayText(),
                            link.targetUrl()))
                    .toList();
            ctx.json(scanner.scan(new Email(
                    request.subject() == null ? "" : request.subject(),
                    request.body(),
                    links)));
        });
        app.get("/health", ctx -> ctx.json(Map.of("status", "ok")));
        app.start("127.0.0.1", 8080);
    }

    public record ScanRequest(String subject, String body, List<LinkRequest> links) {
    }

    public record LinkRequest(String displayText, String targetUrl) {
    }
}
