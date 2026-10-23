const API_URL = "http://127.0.0.1:8080/api/scan";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "PHISHGUARD_SCAN_ACTIVE_TAB") return;

  scanActiveTab()
    .then(sendResponse)
    .catch((error) => sendResponse({ error: error.message }));
  return true;
});

async function scanActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("Could not find the active tab.");

  let extracted;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"]
    });
    void results;
    extracted = await chrome.tabs.sendMessage(tab.id, { type: "PHISHGUARD_EXTRACT_MESSAGE" });
  } catch {
    throw new Error("This page does not allow message scanning. Try a regular email page.");
  }
  if (extracted?.error) throw new Error(extracted.error);

  let response;
  try {
    response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extracted)
    });
  } catch {
    throw new Error("Could not reach the local scanner. Start the PhishGuard server and check its extension-origin setup.");
  }
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Scanner returned HTTP ${response.status}.`);
  return result;
}
