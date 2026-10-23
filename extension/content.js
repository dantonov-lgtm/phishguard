(() => {
  const MAX_TEXT_LENGTH = 15000;
  const MAX_LINKS = 50;
  if (globalThis.__phishGuardListenerInstalled) return;
  globalThis.__phishGuardListenerInstalled = true;

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== "PHISHGUARD_EXTRACT_MESSAGE") return;

    const selection = window.getSelection();
    const selectedText = selection?.toString().trim() ?? "";
    const body = (selectedText || document.body?.innerText || "").slice(0, MAX_TEXT_LENGTH);
    const subject = document.querySelector("h1, .hP, [data-testid='message-subject']")
      ?.innerText?.trim().slice(0, 300) ?? "";
    const selectedFragment = selectedText && selection?.rangeCount
      ? selection.getRangeAt(0).cloneContents()
      : null;
    const linkSource = selectedFragment || document;
    const links = Array.from(linkSource.querySelectorAll("a[href]"))
      .filter((anchor) => anchor.innerText.trim() || anchor.href)
      .slice(0, MAX_LINKS)
      .map((anchor) => ({
        displayText: anchor.innerText.trim().slice(0, 500),
        targetUrl: anchor.href
      }));

    if (!body.trim()) {
      sendResponse({ error: "No readable message text was found on this page." });
      return;
    }
    sendResponse({ subject, body, links });
  });
})();
