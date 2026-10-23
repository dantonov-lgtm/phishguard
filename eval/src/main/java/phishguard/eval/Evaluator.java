package phishguard.eval;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import phishguard.engine.Email;
import phishguard.engine.PhishingScanner;
import phishguard.engine.ScanResult;

public final class Evaluator {
    private Evaluator() {
    }

    public static void main(String[] args) throws IOException {
        Path dataset = args.length == 0
                ? Path.of("eval/data/sample-emails.csv")
                : Path.of(args[0]);
        List<String> lines = Files.readAllLines(dataset);
        if (lines.size() < 2) {
            throw new IllegalArgumentException("Dataset must contain a header and at least one labeled row.");
        }

        int truePositives = 0;
        int falsePositives = 0;
        int falseNegatives = 0;
        PhishingScanner scanner = new PhishingScanner();
        for (int lineNumber = 2; lineNumber <= lines.size(); lineNumber++) {
            List<String> fields = parseCsvLine(lines.get(lineNumber - 1));
            if (fields.size() != 3) {
                throw new IllegalArgumentException("Expected 3 columns at CSV line " + lineNumber);
            }
            boolean actualPhishing = switch (fields.get(0).trim().toUpperCase()) {
                case "PHISHING" -> true;
                case "LEGITIMATE" -> false;
                default -> throw new IllegalArgumentException("Unknown label at CSV line " + lineNumber);
            };
            Email email = new Email(fields.get(1), fields.get(2), List.of());
            ScanResult result = scanner.scan(email);
            boolean predictedPhishing = result.risk() != ScanResult.Risk.LOW;

            if (predictedPhishing && actualPhishing) truePositives++;
            else if (predictedPhishing) falsePositives++;
            else if (actualPhishing) falseNegatives++;
        }

        int actualPositives = truePositives + falseNegatives;
        double precision = divide(truePositives, truePositives + falsePositives);
        double recall = divide(truePositives, actualPositives);
        System.out.printf("Messages evaluated: %d%n", lines.size() - 1);
        System.out.printf("Phishing threshold: MEDIUM or HIGH%n");
        System.out.printf("True positives: %d | False positives: %d | False negatives: %d%n",
                truePositives, falsePositives, falseNegatives);
        System.out.printf("Precision: %.3f%n", precision);
        System.out.printf("Recall:    %.3f%n", recall);
        if (actualPositives == 0) {
            throw new IllegalArgumentException("Dataset must include at least one PHISHING example.");
        }
    }

    private static double divide(int numerator, int denominator) {
        return denominator == 0 ? 0.0 : (double) numerator / denominator;
    }

    private static List<String> parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char character = line.charAt(i);
            if (character == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    field.append('"');
                    i++;
                } else {
                    quoted = !quoted;
                }
            } else if (character == ',' && !quoted) {
                fields.add(field.toString());
                field.setLength(0);
            } else {
                field.append(character);
            }
        }
        if (quoted) {
            throw new IllegalArgumentException("Unclosed quote in CSV row.");
        }
        fields.add(field.toString());
        return fields;
    }
}
