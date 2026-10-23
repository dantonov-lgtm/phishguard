package phishguard.engine;

import java.util.List;
import java.util.regex.Pattern;

final class UrgencyHeuristic implements Heuristic {
    private static final Pattern URGENCY = Pattern.compile(
            "\\b(urgent(?:ly)?|immediately|act now|within 24 hours|account (?:will be|is) (?:closed|suspended|locked)|final warning|expires today)\\b",
            Pattern.CASE_INSENSITIVE);

    @Override
    public List<Finding> analyze(Email email) {
        String text = email.subject() + "\n" + email.body();
        if (!URGENCY.matcher(text).find()) {
            return List.of();
        }
        return List.of(new Finding(
                "urgent-language",
                Finding.Severity.MEDIUM,
                "The message uses urgent or threatening language to pressure a quick response.",
                20));
    }
}
