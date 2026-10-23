package phishguard.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PhishingScannerTest {
    private final PhishingScanner scanner = new PhishingScanner();

    @Test
    void flagsUrgencyAndCredentialRequestsAsHighRisk() {
        ScanResult result = scanner.scan(new Email(
                "Urgent: account suspended",
                "Verify your password immediately to restore access.",
                List.of()));

        assertEquals(ScanResult.Risk.HIGH, result.risk());
        assertTrue(result.findings().stream().anyMatch(f -> f.id().equals("urgent-language")));
        assertTrue(result.findings().stream().anyMatch(f -> f.id().equals("credential-request")));
    }

    @Test
    void flagsDisplayedDestinationMismatch() {
        ScanResult result = scanner.scan(new Email(
                "Your invoice",
                "Please review the document.",
                List.of(new EmailLink("https://trusted.example", "https://attacker.example/login"))));

        assertTrue(result.findings().stream().anyMatch(f -> f.id().equals("link-destination-mismatch")));
        assertEquals(ScanResult.Risk.MEDIUM, result.risk());
    }

    @Test
    void doesNotCallAnUnflaggedMessageSafe() {
        ScanResult result = scanner.scan(new Email(
                "Team lunch",
                "See you at noon.",
                List.of()));

        assertEquals(ScanResult.Risk.LOW, result.risk());
        assertTrue(result.guidance().contains("not proof"));
        assertFalse(result.guidance().toLowerCase().contains("safe to open"));
    }
}
