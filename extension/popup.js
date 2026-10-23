const button = document.querySelector("#scan");
const result = document.querySelector("#result");

button.addEventListener("click", async () => {
  button.disabled = true;
  button.textContent = "Scanning…";
  result.hidden = false;
  result.removeAttribute("data-risk");
  result.textContent = "Analyzing locally…";

  try {
    const response = await chrome.runtime.sendMessage({ type: "PHISHGUARD_SCAN_ACTIVE_TAB" });
    if (response?.error) throw new Error(response.error);
    renderResult(response);
  } catch (error) {
    result.removeAttribute("data-risk");
    result.textContent = error.message || "The scan failed.";
  } finally {
    button.disabled = false;
    button.textContent = "Scan open message";
  }
});

function renderResult(scan) {
  result.dataset.risk = scan.risk;
  const heading = document.createElement("h2");
  heading.textContent = `${scan.risk} risk · score ${scan.score}/100`;
  const guidance = document.createElement("p");
  guidance.textContent = scan.guidance;
  result.replaceChildren(heading, guidance);

  if (scan.findings.length > 0) {
    const list = document.createElement("ul");
    for (const finding of scan.findings) {
      const item = document.createElement("li");
      item.textContent = finding.description;
      list.append(item);
    }
    result.append(list);
  }
}
