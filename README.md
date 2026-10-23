# PhishGuard

PhishGuard is a local, defensive email-warning prototype. It checks message text and link metadata for a small set of common phishing indicators. It does not visit links, download attachments, contact reputation services, or prove that any message is safe.

## Components

- `engine/` — pure Java heuristics and typed scan results.
- `server/` — Javalin API on `127.0.0.1:8080`.
- `extension/` — Chrome Manifest V3 popup; scanning starts only when the user clicks the button.
- `eval/` — precision/recall runner and a tiny illustrative CSV dataset.

## Build and test

Requires JDK 17+ and Maven.

```sh
mvn test
mvn install -DskipTests
mvn -pl eval exec:java
```

The sample dataset is intentionally small and synthetic; its metrics are not evidence of production accuracy. Replace it with a representative, consented, correctly labeled dataset before drawing conclusions.

## Run the local API

```sh
mvn install -DskipTests
mvn -pl server exec:java
```

The API listens on loopback only. `GET /health` reports server health. `POST /api/scan` accepts JSON:

```json
{
  "subject": "Example subject",
  "body": "Example message text",
  "links": [
    {"displayText": "https://example.com", "targetUrl": "https://example.com/path"}
  ]
}
```

The server limits requests to 64 KiB and 50 links. Browsers send an `Origin` header for extension requests. Set `PHISHGUARD_EXTENSION_ORIGIN` to the exact installed extension origin (for example `chrome-extension://your-extension-id`) before starting the server. Requests carrying any other origin are rejected. Requests without an `Origin` header remain available to local command-line clients.

## Load the Chrome extension

1. Start the local API and set its allowed extension origin as described above.
2. Open `chrome://extensions`, enable Developer mode, and choose **Load unpacked**.
3. Select the `extension/` directory and copy its extension ID.
4. If this is the first load, restart the server with `PHISHGUARD_EXTENSION_ORIGIN=chrome-extension://<extension-id>`.
5. Open an email, select its message text if the page has a lot of surrounding content, then click the extension and choose **Scan open message**.

The extension extracts selected text when available; otherwise it reads visible page text and up to 50 links. It sends that content to the local server only. Scanning is user-triggered and does not block opening links or attachments. A low-risk result means only that these heuristics found no strong indicators.

## API behavior

Risk levels are heuristic score bands: LOW (0–19), MEDIUM (20–49), HIGH (50–100). The findings explain which rules matched. False positives and missed threats are expected; always verify unusual requests through a separate trusted channel.
