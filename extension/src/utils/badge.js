export async function setBadge(tabId, score) {
  try {
    const color = getScoreColor(score);
    const text = score.toString();

    await chrome.action.setBadgeBackgroundColor({ color, tabId });
    await chrome.action.setBadgeText({ text, tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge set error:", error);
  }
}

export async function setBadgeSafe(tabId) {
  try {
    await chrome.action.setBadgeBackgroundColor({
      color: "#10b981",
      tabId,
    });
    await chrome.action.setBadgeText({ text: "✓", tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge safe error:", error);
  }
}

export async function setBadgeWarning(tabId, score) {
  try {
    await chrome.action.setBadgeBackgroundColor({
      color: "#f59e0b",
      tabId,
    });
    await chrome.action.setBadgeText({ text: score.toString(), tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge warning error:", error);
  }
}

export async function setBadgeDanger(tabId, score) {
  try {
    await chrome.action.setBadgeBackgroundColor({
      color: "#ef4444",
      tabId,
    });
    await chrome.action.setBadgeText({ text: score.toString(), tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge danger error:", error);
  }
}

export async function setBadgeError(tabId) {
  try {
    await chrome.action.setBadgeBackgroundColor({
      color: "#6b7280",
      tabId,
    });
    await chrome.action.setBadgeText({ text: "?", tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge error:", error);
  }
}

export async function clearBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ text: "", tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge clear error:", error);
  }
}

function getScoreColor(score) {
  if (score < 20) return "#10b981";
  if (score < 40) return "#10b981";
  if (score < 60) return "#f59e0b";
  if (score < 80) return "#ef4444";
  return "#ef4444";
}
