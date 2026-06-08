document.addEventListener("DOMContentLoaded", async () => {
  const gaugeArc = document.getElementById("gaugeArc");
  const scoreText = document.getElementById("scoreText");
  const threatLevel = document.getElementById("threatLevel");
  const signalsList = document.getElementById("signalsList");
  const currentDomain = document.getElementById("currentDomain");
  const sslStatus = document.getElementById("sslStatus");
  const domainAge = document.getElementById("domainAge");
  const proceedBtn = document.getElementById("proceedBtn");
  const blockBtn = document.getElementById("blockBtn");
  const reportBtn = document.getElementById("reportBtn");
  const historyList = document.getElementById("historyList");
  const statusDot = document.getElementById("statusDot");
  const openDashboard = document.getElementById("openDashboard");
  const openSettings = document.getElementById("openSettings");

  const CIRCUMFERENCE = 534;
  let currentScore = 0;

  function setGauge(score, level) {
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    gaugeArc.style.strokeDashoffset = offset;

    let color;
    switch (level) {
      case "safe":
      case "low":
        color = "#10b981";
        break;
      case "medium":
        color = "#f59e0b";
        break;
      case "high":
      case "critical":
        color = "#ef4444";
        break;
      default:
        color = "#64748b";
    }
    gaugeArc.style.stroke = color;

    scoreText.textContent = score;
    threatLevel.textContent = level?.toUpperCase() || "UNKNOWN";
    threatLevel.className = `threat-level ${level || ""}`;
  }

  function renderSignals(signals) {
    if (!signals || signals.length === 0) {
      signalsList.innerHTML =
        '<div style="color: #64748b; font-size: 13px; text-align: center; padding: 16px;">No threats detected</div>';
      return;
    }

    signalsList.innerHTML = signals
      .map(
        (s) => `
      <div class="signal-item">
        <span class="signal-name">${escapeHtml(s.name)}</span>
        <span class="signal-severity ${s.severity}">${s.severity}</span>
      </div>
    `
      )
      .join("");
  }

  function renderHistory(history) {
    if (!history || history.length === 0) {
      historyList.innerHTML =
        '<div style="color: #64748b; font-size: 12px; text-align: center; padding: 12px;">No recent scans</div>';
      return;
    }

    historyList.innerHTML = history
      .slice(0, 5)
      .map(
        (h) => `
      <div class="history-item">
        <span class="history-domain">${escapeHtml(h.domain)}</span>
        <span class="history-score ${getScoreClass(h.riskScore)}">${h.riskScore}</span>
      </div>
    `
      )
      .join("");
  }

  function getScoreClass(score) {
    if (score < 20) return "safe";
    if (score < 40) return "low";
    if (score < 60) return "medium";
    if (score < 80) return "high";
    return "critical";
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (tab?.url) {
      try {
        const parsed = new URL(tab.url);
        currentDomain.textContent = parsed.hostname;

        const isHttps = parsed.protocol === "https:";
        sslStatus.innerHTML = `<span class="meta-dot ${isHttps ? "green" : "red"}"></span>${isHttps ? "HTTPS Secure" : "HTTP Insecure"}`;
      } catch {
        currentDomain.textContent = tab.url;
      }
    }

    chrome.runtime.sendMessage({ type: "GET_CURRENT_SCAN" }, (response) => {
      if (chrome.runtime.lastError) {
        console.error("Error getting scan:", chrome.runtime.lastError);
        return;
      }

      if (response) {
        currentScore = response.risk_score;
        setGauge(response.risk_score, response.threat_level);
        renderSignals(response.signals);

        proceedBtn.disabled = response.risk_score <= 30;

        domainAge.innerHTML = `<span class="meta-dot ${response.risk_score > 50 ? "yellow" : "green"}"></span>Scanned ${new Date().toLocaleTimeString()}`;
      } else {
        setGauge(0, "safe");
        signalsList.innerHTML =
          '<div style="color: #64748b; font-size: 13px; text-align: center; padding: 16px;">No scan data available</div>';
      }
    });

    chrome.runtime.sendMessage({ type: "GET_HISTORY" }, (history) => {
      if (!chrome.runtime.lastError) {
        renderHistory(history);
      }
    });
  } catch (error) {
    console.error("Popup init error:", error);
    setGauge(0, "safe");
  }

  proceedBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "PROCEED_ANYWAY" }, () => {
      window.close();
    });
  });

  blockBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.update(tabs[0].id, { url: "about:blank" });
      }
    });
    window.close();
  });

  reportBtn.addEventListener("click", () => {
    chrome.tabs.create({
      url: `http://localhost:3000/report?url=${encodeURIComponent(
        currentDomain.textContent
      )}`,
    });
  });

  openDashboard.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: "http://localhost:3000/dashboard" });
  });

  openSettings.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
});
