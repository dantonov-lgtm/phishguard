package phishguard.engine;

import java.util.List;
import java.util.regex.Pattern;

final class CredentialRequestHeuristic implements Heuristic {
    private static final Pattern CREDENTIAL_REQUEST = Pattern.compile(
            "\\b(verify|confirm|update|reset|provide|enter|submit)\\b.{0,60}\\b(password|passcode|login|credentials|account details|security code)\\b"
                    + "|\\b(password|passcode|credentials|security code)\\b.{0,60}\\b(verify|confirm|update|reset|provide|enter|submit)\\b",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    @Override
    public List<Finding> analyze(Email email) {
        String text = email.subject() + "\n" + email.body();
        if (!CREDENTIAL_REQUEST.matcher(text).find()) {
            return List.of();
        }
        return List.of(new Finding(
                "credential-request",
                Finding.Severity.HIGH,
                "The message appears to ask the recipient to provide or verify credentials or security codes.",
                40));
    }
}
