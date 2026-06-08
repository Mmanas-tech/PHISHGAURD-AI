const API_BASE_URL = "http://localhost:8000";
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_HISTORY = 500;

const scanCache = new Map();
const scanningTabs = new Set();

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    settings: {
      protectionLevel: "balanced",
      whitelist: [],
      blacklist: [],
      notificationsEnabled: true,
    },
    scanHistory: [],
  });

  chrome.alarms.create("cleanup-cache", { periodInMinutes: 10 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "cleanup-cache") {
    cleanupCache();
  }
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;
  const tabId = details.tabId;

  if (shouldSkipUrl(url)) return;
  if (scanningTabs.has(tabId)) return;

  const cached = scanCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    await updateBadge(tabId, cached.result.risk_score);
    return;
  }

  scanningTabs.add(tabId);

  try {
    const settings = await getSettings();
    if (settings.whitelist.some((d) => url.includes(d))) {
      await setBadgeSafe(tabId);
      return;
    }

    const result = await scanUrl(url);

    scanCache.set(url, { result, timestamp: Date.now() });

    await updateBadge(tabId, result.risk_score);

    await saveToHistory({
      url: result.url,
      domain: result.domain,
      riskScore: result.risk_score,
      threatLevel: result.threat_level,
      threatType: result.threat_type,
      timestamp: Date.now(),
    });

    if (result.risk_score > 70) {
      if (settings.notificationsEnabled) {
        showThreatNotification(result);
      }
      await injectBlockingPage(tabId, result);
    } else if (result.risk_score > 30) {
      if (settings.notificationsEnabled) {
        showWarningNotification(result);
      }
    }
  } catch (error) {
    console.error("[PhishGuard] Scan error:", error);
    await setBadgeError(tabId);
  } finally {
    scanningTabs.delete(tabId);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_CURRENT_SCAN") {
    const tabId = sender.tab?.id;
    if (tabId) {
      chrome.tabs.get(tabId, async (tab) => {
        if (tab?.url) {
          const cached = scanCache.get(tab.url);
          sendResponse(cached?.result || null);
        } else {
          sendResponse(null);
        }
      });
      return true;
    }
  }

  if (message.type === "MANUAL_SCAN") {
    scanUrl(message.url)
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ error: error.message }));
    return true;
  }

  if (message.type === "GET_HISTORY") {
    getHistory()
      .then((history) => sendResponse(history))
      .catch(() => sendResponse([]));
    return true;
  }

  if (message.type === "GET_SETTINGS") {
    getSettings()
      .then((settings) => sendResponse(settings))
      .catch(() => sendResponse({}));
    return true;
  }

  if (message.type === "UPDATE_SETTINGS") {
    updateSettings(message.settings)
      .then(() => sendResponse({ success: true }))
      .catch(() => sendResponse({ success: false }));
    return true;
  }

  if (message.type === "PROCEED_ANYWAY") {
    const tabId = sender.tab?.id;
    if (tabId) {
      chrome.scripting.executeScript({
        target: { tabId },
        func: () => {
          const overlay = document.getElementById("phishguard-block-overlay");
          if (overlay) overlay.remove();
        },
      });
    }
    sendResponse({ success: true });
    return true;
  }
});

function shouldSkipUrl(url) {
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("file://") ||
    url.startsWith("data:")
  ) {
    return true;
  }

  try {
    const parsed = new URL(url);
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
      return true;
    }
  } catch {
    return true;
  }

  return false;
}

async function scanUrl(url) {
  const token = await getAuthToken();

  const headers = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetchWithRetry(`${API_BASE_URL}/api/v1/scan`, {
    method: "POST",
    headers,
    body: JSON.stringify({ url }),
  });

  return response;
}

async function fetchWithRetry(url, options, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      if (i === retries - 1) throw error;
      await new Promise((r) => setTimeout(r, Math.pow(2, i) * 500));
    }
  }
}

async function getAuthToken() {
  try {
    const data = await chrome.storage.local.get(["authToken"]);
    return data.authToken || null;
  } catch {
    return null;
  }
}

async function getSettings() {
  const data = await chrome.storage.local.get(["settings"]);
  return (
    data.settings || {
      protectionLevel: "balanced",
      whitelist: [],
      blacklist: [],
      notificationsEnabled: true,
    }
  );
}

async function updateSettings(newSettings) {
  const current = await getSettings();
  const updated = { ...current, ...newSettings };
  await chrome.storage.local.set({ settings: updated });
}

async function updateBadge(tabId, riskScore) {
  try {
    const color = riskScore > 70 ? "#ef4444" : riskScore > 30 ? "#f59e0b" : "#10b981";
    const text = riskScore.toString();

    await chrome.action.setBadgeBackgroundColor({ color, tabId });
    await chrome.action.setBadgeText({ text, tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge update error:", error);
  }
}

async function setBadgeSafe(tabId) {
  try {
    await chrome.action.setBadgeBackgroundColor({
      color: "#10b981",
      tabId,
    });
    await chrome.action.setBadgeText({ text: "✓", tabId });
  } catch (error) {
    console.error("[PhishGuard] Badge error:", error);
  }
}

async function setBadgeError(tabId) {
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

function showThreatNotification(result) {
  chrome.notifications.create(`threat-${Date.now()}`, {
    type: "basic",
    iconUrl: "assets/icon128.png",
    title: "Phishing Threat Detected!",
    message: `${result.domain} has been flagged as ${result.threat_level} risk (${result.risk_score}/100)`,
    priority: 2,
  });
}

function showWarningNotification(result) {
  chrome.notifications.create(`warning-${Date.now()}`, {
    type: "basic",
    iconUrl: "assets/icon128.png",
    title: "Suspicious Site Warning",
    message: `${result.domain} has suspicious indicators (risk: ${result.risk_score}/100)`,
    priority: 1,
  });
}

async function injectBlockingPage(tabId, result) {
  try {
    const blockedUrl = chrome.runtime.getURL("src/pages/blocked.html");
    const params = new URLSearchParams({
      url: result.url,
      domain: result.domain,
      score: result.risk_score.toString(),
      level: result.threat_level,
      type: result.threat_type,
      signals: JSON.stringify(result.signals || []),
    });

    await chrome.tabs.update(tabId, {
      url: `${blockedUrl}?${params.toString()}`,
    });
  } catch (error) {
    console.error("[PhishGuard] Block page injection error:", error);
  }
}

async function saveToHistory(entry) {
  try {
    const data = await chrome.storage.local.get(["scanHistory"]);
    const history = data.scanHistory || [];
    history.unshift(entry);
    if (history.length > MAX_HISTORY) {
      history.splice(MAX_HISTORY);
    }
    await chrome.storage.local.set({ scanHistory: history });
  } catch (error) {
    console.error("[PhishGuard] History save error:", error);
  }
}

async function getHistory() {
  const data = await chrome.storage.local.get(["scanHistory"]);
  return data.scanHistory || [];
}

function cleanupCache() {
  const now = Date.now();
  for (const [key, value] of scanCache.entries()) {
    if (now - value.timestamp > CACHE_TTL_MS) {
      scanCache.delete(key);
    }
  }
}
