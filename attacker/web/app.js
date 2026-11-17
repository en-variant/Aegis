const caseList = document.querySelector("#case-list");
const results = document.querySelector("#results");
const runButton = document.querySelector("#run-button");
const runStatus = document.querySelector("#run-status");
const runSummary = document.querySelector("#run-summary");
const tokenInput = document.querySelector("#app-token");

function addText(parent, tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  parent.append(element);
  return element;
}

async function loadCases() {
  try {
    const response = await fetch("/api/cases");
    if (!response.ok) throw new Error("Unable to load the test catalog.");
    const cases = await response.json();
    caseList.replaceChildren();
    cases.forEach((testCase, index) => {
      const item = document.createElement("li");
      item.className = "case-item";
      addText(item, "span", "case-number", String(index + 1).padStart(2, "0"));
      const description = document.createElement("div");
      addText(description, "p", "case-title", testCase.label);
      addText(description, "p", "case-description", testCase.description);
      item.append(description);
      caseList.append(item);
    });
  } catch (error) {
    caseList.replaceChildren();
    addText(caseList, "li", "case-loading", error.message);
  }
}

function renderResults(data) {
  const list = document.createElement("div");
  list.className = "result-list";
  data.results.forEach((result) => {
    const card = document.createElement("article");
    card.className = "result-card";
    addText(card, "span", `result-icon ${result.passed ? "pass" : "fail"}`, result.passed ? "✓" : "!");
    const title = document.createElement("div");
    addText(title, "p", "result-name", result.label);
    addText(
      title,
      "p",
      "result-detail",
      result.expected_reason
        ? `Expected ${result.expected_reason} · got ${result.reason}`
        : `Expected ${result.expected_allowed ? "allow" : "block"} · got ${result.allowed ? "allow" : "block"}`,
    );
    card.append(title);
    addText(card, "p", "result-reason", result.reason || "No decision reason was returned.");
    const decision = addText(card, "span", `decision ${result.allowed ? "allowed" : "blocked"}`, result.allowed ? "ALLOWED" : "BLOCKED");
    decision.setAttribute("aria-label", `Decision: ${result.allowed ? "allowed" : "blocked"}`);
    const extras = [];
    if (result.incident_id) extras.push(`Incident ${result.incident_id}`);
    if (result.proposal_status) extras.push(`Blue proposal ${result.proposal_status}`);
    extras.push(result.side_effect);
    addText(card, "p", "result-foot", extras.join(" · "));
    list.append(card);
  });
  results.replaceChildren(list);
  runSummary.textContent = `${data.passed_count}/${data.total} CHECKS PASSED`;
  runSummary.style.color = data.passed ? "var(--cyan)" : "var(--red)";
  const meta = document.createElement("p");
  meta.className = "run-meta";
  meta.textContent = `RUN ${data.run_id} · ${data.execution_mode.toUpperCase()} · ${data.target.toUpperCase()}`;
  results.append(meta);
}

runButton.addEventListener("click", async () => {
  const token = tokenInput.value.trim();
  if (!token) {
    runStatus.textContent = "Enter the app integration token for the selected local app.";
    runStatus.className = "run-status error";
    tokenInput.focus();
    return;
  }

  runButton.disabled = true;
  runStatus.textContent = "Running five authorization-only probes…";
  runStatus.className = "run-status";
  runSummary.textContent = "RUNNING";
  runSummary.style.color = "var(--muted)";
  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        aegis_url: document.querySelector("#aegis-url").value.trim(),
        app_token: token,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Test run failed.");
    renderResults(data);
    runStatus.textContent = "Run complete. The token was used for this request only.";
    tokenInput.value = "";
  } catch (error) {
    runSummary.textContent = "RUN FAILED";
    runSummary.style.color = "var(--red)";
    runStatus.textContent = error.message;
    runStatus.className = "run-status error";
  } finally {
    tokenInput.value = "";
    runButton.disabled = false;
  }
});

loadCases();
