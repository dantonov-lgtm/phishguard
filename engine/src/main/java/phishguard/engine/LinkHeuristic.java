package phishguard.engine;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class LinkHeuristic implements Heuristic {
    private static final Pattern URL_IN_TEXT = Pattern.compile(
            "(?i)\\bhttps?://[^\\s<>\"']+");
    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "cutt.ly", "buff.ly");

    @Override
    public List<Finding> analyze(Email email) {
        List<Finding> findings = new ArrayList<>();
        for (EmailLink link : email.links()) {
            inspectLink(link, findings);
        }
        Matcher urls = URL_IN_TEXT.matcher(email.body());
        while (urls.find()) {
            inspectTarget(urls.group(), findings);
        }
        return List.copyOf(findings);
    }

    private void inspectLink(EmailLink link, List<Finding> findings) {
        URI target = parse(link.targetUrl());
        String displayHost = hostFromDisplayText(link.displayText());
        if (target != null && displayHost != null
                && !normalizeHost(displayHost).equals(normalizeHost(target.getHost()))) {
            findings.add(new Finding(
                    "link-destination-mismatch",
                    Finding.Severity.HIGH,
                    "A link's displayed web address does not match its actual destination.",
                    45));
        }
        inspectTarget(link.targetUrl(), findings);
    }

    private void inspectTarget(String value, List<Finding> findings) {
        URI uri = parse(value);
        if (uri == null) {
            return;
        }
        String host = normalizeHost(uri.getHost());
        if (uri.getUserInfo() != null) {
            findings.add(new Finding(
                    "link-contains-user-info",
                    Finding.Severity.HIGH,
                    "A link contains text before the host that can disguise its true destination.",
                    35));
        }
        if (host.startsWith("xn--") || host.contains(".xn--")) {
            findings.add(new Finding(
                    "internationalized-link-host",
                    Finding.Severity.MEDIUM,
                    "A link uses an encoded internationalized domain name; verify the domain carefully.",
                    20));
        }
        if (SHORTENERS.contains(host)) {
            findings.add(new Finding(
                    "shortened-link",
                    Finding.Severity.MEDIUM,
                    "A link uses a URL-shortening service, which hides its final destination.",
                    20));
        }
        if (isIpAddress(host)) {
            findings.add(new Finding(
                    "ip-address-link",
                    Finding.Severity.MEDIUM,
                    "A link points directly to an IP address instead of a recognizable domain.",
                    25));
        }
    }

    private static URI parse(String value) {
        try {
            URI uri = new URI(value.trim());
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            return uri;
        } catch (URISyntaxException exception) {
            return null;
        }
    }

    private static String hostFromDisplayText(String text) {
        String candidate = text.trim();
        if (!candidate.matches("(?i)^(https?://|www\\.).*")) {
            return null;
        }
        URI uri = parse(candidate.startsWith("www.") ? "https://" + candidate : candidate);
        return uri == null ? null : uri.getHost();
    }

    private static String normalizeHost(String host) {
        return host == null ? "" : host.toLowerCase(Locale.ROOT).replaceFirst("^www\\.", "");
    }

    private static boolean isIpAddress(String host) {
        if (host == null || !host.matches("[0-9.]+")) {
            return false;
        }
        try {
            return InetAddress.getByName(host).getHostAddress().equals(host);
        } catch (Exception exception) {
            return false;
        }
    }
}
