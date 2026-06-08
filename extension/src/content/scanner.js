(function () {
  "use strict";

  if (window.__phishguard_loaded) return;
  window.__phishguard_loaded = true;

  const signals = {
    passwordFields: 0,
    creditCardFields: 0,
    loginForms: 0,
    hiddenElements: 0,
    iframes: 0,
    externalScripts: 0,
    obfuscatedJs: 0,
    hasHttps: location.protocol === "https:",
    formActions: [],
    metaRefresh: false,
    javascriptHrefs: 0,
  };

  function analyzePage() {
    signals.passwordFields = document.querySelectorAll(
      'input[type="password"]'
    ).length;

    signals.creditCardFields = document.querySelectorAll(
      'input[autocomplete="cc-number"], input[autocomplete="cc-exp"], input[autocomplete="cc-csc"], input[name*="card"], input[id*="card"], input[placeholder*="card"]'
    ).length;

    const loginPatterns = [
      'input[type="password"]',
      'input[name*="pass"]',
      'input[name*="login"]',
      'input[name*="email"]',
      'input[name*="user"]',
    ];
    const loginElements = new Set();
    loginPatterns.forEach((sel) => {
      document.querySelectorAll(sel).forEach((el) => loginElements.add(el));
    });
    signals.loginForms = loginElements.size > 0 ? 1 : 0;

    signals.hiddenElements = document.querySelectorAll(
      '[style*="display: none"], [style*="visibility: hidden"], input[type="hidden"]'
    ).length;

    signals.iframes = document.querySelectorAll("iframe").length;

    const scripts = document.querySelectorAll("script[src]");
    const currentDomain = location.hostname;
    signals.externalScripts = Array.from(scripts).filter((s) => {
      try {
        const url = new URL(s.src);
        return url.hostname !== currentDomain;
      } catch {
        return false;
      }
    }).length;

    const scriptContents = document.querySelectorAll("script:not([src])");
    signals.obfuscatedJs = Array.from(scriptContents).filter((s) => {
      const text = s.textContent || "";
      return (
        text.includes("eval(") ||
        text.includes("atob(") ||
        text.includes("fromCharCode") ||
        /\\x[0-9a-fA-F]{2}/.test(text) ||
        /\\u[0-9a-fA-F]{4}/.test(text)
      );
    }).length;

    const forms = document.querySelectorAll("form[action]");
    signals.formActions = Array.from(forms)
      .map((f) => f.action)
      .filter((a) => a && !a.startsWith("#"));

    signals.metaRefresh = !!document.querySelector(
      'meta[http-equiv="refresh"]'
    );

    signals.javascriptHrefs = document.querySelectorAll(
      'a[href^="javascript:"]'
    ).length;
  }

  function calculateLocalRisk() {
    let score = 0;

    if (signals.passwordFields > 0 && !signals.hasHttps) score += 30;
    if (signals.creditCardFields > 0) score += 25;
    if (signals.obfuscatedJs > 0) score += 20;
    if (signals.iframes > 3) score += 15;
    if (signals.javascriptHrefs > 0) score += 15;
    if (signals.metaRefresh) score += 10;
    if (signals.hiddenElements > 10) score += 10;

    return Math.min(100, score);
  }

  function injectWarningBanner(result) {
    if (document.getElementById("phishguard-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phishguard-warning-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
      color: white;
      padding: 12px 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      animation: phishguard-slide-down 0.3s ease-out;
    `;

    const signalNames = (result.signals || [])
      .slice(0, 3)
      .map((s) => s.name)
      .join(", ");

    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span>
          <strong>PhishGuard Warning:</strong> This site has suspicious indicators
          ${signalNames ? ` (${signalNames})` : ""}
        </span>
      </div>
      <button id="phishguard-dismiss" style="
        background: rgba(255,255,255,0.2);
        border: none;
        color: white;
        padding: 4px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 12px;
      ">Dismiss</button>
    `;

    document.body.prepend(banner);

    const style = document.createElement("style");
    style.textContent = `
      @keyframes phishguard-slide-down {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
      }
    `;
    document.head.appendChild(style);

    document
      .getElementById("phishguard-dismiss")
      ?.addEventListener("click", () => {
        banner.remove();
      });
  }

  try {
    analyzePage();

    const localRisk = calculateLocalRisk();

    chrome.runtime.sendMessage({
      type: "PAGE_SIGNALS",
      payload: {
        url: location.href,
        domain: location.hostname,
        signals,
        localRisk,
      },
    });

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === "GET_PAGE_SIGNALS") {
        sendResponse({ signals, localRisk });
      }
    });

    chrome.runtime.sendMessage(
      { type: "GET_CURRENT_SCAN" },
      (response) => {
        if (chrome.runtime.lastError) return;
        if (response && response.risk_score > 70) {
          injectWarningBanner(response);
        }
      }
    );
  } catch (error) {
    console.error("[PhishGuard] Scanner error:", error);
  }
})();
