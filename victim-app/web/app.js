const loginPanel = document.querySelector("#login-panel");
const assistantPanel = document.querySelector("#assistant-panel");
const loginStatus = document.querySelector("#login-status");
const chatStatus = document.querySelector("#chat-status");
const answerPanel = document.querySelector("#answer-panel");
const answer = document.querySelector("#answer");
const toolResults = document.querySelector("#tool-results");

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}

function showUser(user) {
  loginPanel.hidden = true;
  assistantPanel.hidden = false;
  document.querySelector("#signed-in-user").textContent =
    `${user.id} · ${user.role.replaceAll("_", " ")}`;
}

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  loginStatus.textContent = "Signing in…";
  loginStatus.className = "status";
  const data = new FormData(event.currentTarget);
  try {
    const user = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: data.get("username"),
        password: data.get("password"),
      }),
    });
    event.currentTarget.reset();
    showUser(user);
    loginStatus.textContent = "";
  } catch (error) {
    loginStatus.textContent = error.message;
    loginStatus.className = "status error";
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  assistantPanel.hidden = true;
  loginPanel.hidden = false;
  answerPanel.hidden = true;
  chatStatus.textContent = "";
});

document.querySelector("#chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.querySelector("#send-button");
  button.disabled = true;
  chatStatus.textContent = "Waiting for the local assistant…";
  chatStatus.className = "status";
  answerPanel.hidden = true;
  try {
    const data = await api("/api/chat", {
      method: "POST",
      body: JSON.stringify({ message: document.querySelector("#message").value }),
    });
    answer.textContent = data.answer || "(The assistant returned no text.)";
    toolResults.replaceChildren();
    data.tool_calls.forEach((call) => {
      const item = document.createElement("li");
      item.textContent = `${call.tool}: ${call.result}`;
      toolResults.append(item);
    });
    answerPanel.hidden = false;
    chatStatus.textContent = "Completed. Review the tool decisions below.";
  } catch (error) {
    chatStatus.textContent = error.message;
    chatStatus.className = "status error";
  } finally {
    button.disabled = false;
  }
});

api("/api/me")
  .then(showUser)
  .catch(() => {
    loginPanel.hidden = false;
  });
