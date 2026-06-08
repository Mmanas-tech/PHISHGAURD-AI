export async function storageGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        console.error("[PhishGuard] Storage get error:", chrome.runtime.lastError);
        resolve({});
      } else {
        resolve(result);
      }
    });
  });
}

export async function storageSet(data) {
  return new Promise((resolve) => {
    chrome.storage.local.set(data, () => {
      if (chrome.runtime.lastError) {
        console.error("[PhishGuard] Storage set error:", chrome.runtime.lastError);
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
}

export async function storageRemove(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.remove(keys, () => {
      if (chrome.runtime.lastError) {
        console.error("[PhishGuard] Storage remove error:", chrome.runtime.lastError);
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
}

export async function getSettings() {
  const data = await storageGet(["settings"]);
  return (
    data.settings || {
      protectionLevel: "balanced",
      whitelist: [],
      blacklist: [],
      notificationsEnabled: true,
    }
  );
}

export async function updateSettings(updates) {
  const current = await getSettings();
  const updated = { ...current, ...updates };
  await storageSet({ settings: updated });
  return updated;
}

export async function getAuthToken() {
  const data = await storageGet(["authToken"]);
  return data.authToken || null;
}

export async function setAuthToken(token) {
  await storageSet({ authToken: token });
}

export async function clearAuthToken() {
  await storageRemove(["authToken"]);
}

export async function getScanHistory() {
  const data = await storageGet(["scanHistory"]);
  return data.scanHistory || [];
}

export async function addToHistory(entry) {
  const history = await getScanHistory();
  history.unshift(entry);
  if (history.length > 500) {
    history.splice(500);
  }
  await storageSet({ scanHistory: history });
}

export async function clearHistory() {
  await storageSet({ scanHistory: [] });
}
