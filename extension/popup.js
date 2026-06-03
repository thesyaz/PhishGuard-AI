/**
 * PhishGuard AI - Contrôleur du Popup
 *
 * Gère :
 *  - L'affichage du score et des raisons
 *  - La navigation Analyse / Historique
 *  - Les appels au background script
 *  - L'historique local (chrome.storage.local)
 */

"use strict";

// ---------------------------------------------------------------------------
// Références DOM
// ---------------------------------------------------------------------------

const el = (id) => document.getElementById(id);

const DOM = {
  // États
  stateLoading: el("stateLoading"),
  stateError:   el("stateError"),
  stateResult:  el("stateResult"),
  mainView:     el("mainView"),
  historyView:  el("historyView"),

  // URL bar
  urlText:    el("urlText"),
  urlFavicon: el("urlFavicon"),

  // Score
  scoreNumber: el("scoreNumber"),
  gaugeArc:    el("gaugeArc"),

  // Risk
  riskBadge: el("riskBadge"),
  riskDot:   el("riskDot"),
  riskText:  el("riskText"),

  // Shield icon
  shieldIcon:  el("shieldIcon"),
  shieldCheck: el("shieldCheck"),
  shieldAlert: el("shieldAlert"),

  // AI
  aiSummary: el("aiSummary"),
  aiText:    el("aiText"),

  // Reasons
  reasonsList: el("reasonsList"),

  // Buttons
  analyzeBtn:      el("analyzeBtn"),
  retryBtn:        el("retryBtn"),
  clearHistoryBtn: el("clearHistoryBtn"),

  // Nav
  navAnalysis: el("navAnalysis"),
  navHistory:  el("navHistory"),

  // History
  historyList: el("historyList"),
  statTotal:   el("statTotal"),
  statHigh:    el("statHigh"),
  statMedium:  el("statMedium"),
  statLow:     el("statLow"),
};


// ---------------------------------------------------------------------------
// État de l'application
// ---------------------------------------------------------------------------

let currentTab = null;
let currentResult = null;


// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  await initCurrentTab();
  setupEventListeners();
  await runAnalysis();
});


async function initCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    if (tab?.url) {
      DOM.urlText.textContent = formatURL(tab.url);

      // Favicon
      const faviconURL = `https://www.google.com/s2/favicons?domain=${new URL(tab.url).hostname}&sz=32`;
      const img = document.createElement("img");
      img.src = faviconURL;
      img.onerror = () => { img.style.display = "none"; };
      DOM.urlFavicon.appendChild(img);
    }
  } catch (e) {
    DOM.urlText.textContent = "URL non disponible";
  }
}


// ---------------------------------------------------------------------------
// Analyse principale
// ---------------------------------------------------------------------------

async function runAnalysis(forceRefresh = false) {
  if (!currentTab?.url) {
    showError();
    return;
  }

  showLoading();

  try {
    if (!forceRefresh) {
      // Vérifie d'abord le cache du background
      const cached = await getCachedResult(currentTab.url);
      if (cached) {
        currentResult = cached;
        displayResult(cached);
        return;
      }
    }

    // Lance une nouvelle analyse via le background
    const result = await analyzeNow(currentTab.id, currentTab.url, currentTab.title);
    if (result) {
      currentResult = result;
      displayResult(result);
    } else {
      showError();
    }
  } catch (err) {
    console.error("[PhishGuard Popup]", err);
    showError();
  }
}


function getCachedResult(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_CACHED_RESULT", url }, (resp) => {
      resolve(resp?.result || null);
    });
  });
}


function analyzeNow(tabId, url, title) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { type: "ANALYZE_NOW", tabId, url, title },
      (resp) => {
        if (resp?.success) {
          resolve(resp.result);
        } else {
          resolve(null);
        }
      }
    );
  });
}


// ---------------------------------------------------------------------------
// Affichage des états
// ---------------------------------------------------------------------------

function showLoading() {
  DOM.stateLoading.style.display = "flex";
  DOM.stateError.style.display   = "none";
  DOM.stateResult.style.display  = "none";
}

function showError() {
  DOM.stateLoading.style.display = "none";
  DOM.stateError.style.display   = "flex";
  DOM.stateResult.style.display  = "none";
}

function showResult() {
  DOM.stateLoading.style.display = "none";
  DOM.stateError.style.display   = "none";
  DOM.stateResult.style.display  = "flex";
}


// ---------------------------------------------------------------------------
// Rendu du résultat
// ---------------------------------------------------------------------------

function displayResult(result) {
  showResult();

  const { score, risk, reasons, ai_summary } = result;
  const riskLower = risk.toLowerCase();

  // Score numérique
  DOM.scoreNumber.textContent = score;

  // Jauge (demi-cercle : arc total = 157px de la viewBox)
  const progress = (score / 100) * 157;
  DOM.gaugeArc.style.strokeDashoffset = 157 - progress;
  DOM.gaugeArc.style.setProperty("transition", "stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1)");

  // Couleur de la jauge selon le risque
  const gaugeColors = {
    high:   "#f85149",
    medium: "#e3b341",
    low:    "#3fb950",
  };
  DOM.gaugeArc.setAttribute("stroke", gaugeColors[riskLower] || "#3fb950");
  document.documentElement.style.setProperty("--gauge-color", gaugeColors[riskLower]);

  // Badge risque
  DOM.riskBadge.className = `risk-badge risk-${riskLower}`;
  DOM.riskDot.className   = `risk-dot${risk === "HIGH" ? " pulse" : ""}`;
  const riskLabels = { HIGH: "Risque Élevé", MEDIUM: "Risque Moyen", LOW: "Risque Faible" };
  DOM.riskText.textContent = riskLabels[risk] || risk;

  // Icône bouclier
  DOM.shieldIcon.className = `shield-icon risk-${riskLower}`;
  if (risk === "HIGH" || risk === "MEDIUM") {
    DOM.shieldCheck.style.display = "none";
    DOM.shieldAlert.style.display = "block";
  } else {
    DOM.shieldCheck.style.display = "block";
    DOM.shieldAlert.style.display = "none";
  }

  // Résumé IA
  if (ai_summary) {
    DOM.aiText.textContent = ai_summary;
    DOM.aiSummary.style.display = "block";
  } else {
    DOM.aiSummary.style.display = "none";
  }

  // Liste des raisons
  DOM.reasonsList.innerHTML = "";
  if (reasons && reasons.length > 0) {
    reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.className = `reason-item ${riskLower}`;

      const bullet = document.createElement("span");
      bullet.className = "reason-bullet";

      const text = document.createElement("span");
      text.textContent = reason;

      li.appendChild(bullet);
      li.appendChild(text);
      DOM.reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.className = "reason-item safe";
    const bullet = document.createElement("span");
    bullet.className = "reason-bullet";
    const text = document.createElement("span");
    text.textContent = "Aucun indicateur suspect détecté.";
    li.appendChild(bullet);
    li.appendChild(text);
    DOM.reasonsList.appendChild(li);
  }
}


// ---------------------------------------------------------------------------
// Historique
// ---------------------------------------------------------------------------

async function loadHistory() {
  try {
    const data = await chrome.storage.local.get("phishguard_history");
    const history = data.phishguard_history || [];

    // Statistiques
    const stats = history.reduce(
      (acc, e) => {
        acc.total++;
        if (e.risk === "HIGH") acc.high++;
        else if (e.risk === "MEDIUM") acc.medium++;
        else acc.low++;
        return acc;
      },
      { total: 0, high: 0, medium: 0, low: 0 }
    );

    DOM.statTotal.querySelector(".stat-num").textContent  = stats.total;
    DOM.statHigh.textContent   = stats.high;
    DOM.statMedium.textContent = stats.medium;
    DOM.statLow.textContent    = stats.low;

    // Liste
    DOM.historyList.innerHTML = "";

    if (history.length === 0) {
      DOM.historyList.innerHTML = '<li class="history-empty">Aucune analyse effectuée.</li>';
      return;
    }

    history.slice(0, 30).forEach((entry) => {
      const li = document.createElement("li");
      li.className = "history-item";
      li.title = entry.url;

      const urlSpan = document.createElement("span");
      urlSpan.className = "history-item-url";
      urlSpan.textContent = formatURL(entry.url);

      const scoreSpan = document.createElement("span");
      scoreSpan.className = `history-item-score ${entry.risk.toLowerCase()}`;
      scoreSpan.textContent = `${entry.score}`;

      li.appendChild(urlSpan);
      li.appendChild(scoreSpan);
      DOM.historyList.appendChild(li);
    });
  } catch (e) {
    console.error("[PhishGuard] Chargement historique :", e);
  }
}


async function clearHistory() {
  await chrome.storage.local.set({ phishguard_history: [] });
  await loadHistory();
}


// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

function switchView(view) {
  if (view === "main") {
    DOM.mainView.style.display    = "block";
    DOM.historyView.style.display = "none";
    DOM.navAnalysis.classList.add("active");
    DOM.navHistory.classList.remove("active");
  } else {
    DOM.mainView.style.display    = "none";
    DOM.historyView.style.display = "flex";
    DOM.navAnalysis.classList.remove("active");
    DOM.navHistory.classList.add("active");
    loadHistory();
  }
}


// ---------------------------------------------------------------------------
// Événements
// ---------------------------------------------------------------------------

function setupEventListeners() {
  DOM.analyzeBtn.addEventListener("click", () => runAnalysis(true));
  DOM.retryBtn.addEventListener("click", () => runAnalysis(true));
  DOM.clearHistoryBtn.addEventListener("click", clearHistory);

  DOM.navAnalysis.addEventListener("click", () => switchView("main"));
  DOM.navHistory.addEventListener("click", () => switchView("history"));
}


// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

function formatURL(url) {
  try {
    const u = new URL(url);
    let display = u.hostname + u.pathname;
    if (display.length > 45) display = display.substring(0, 44) + "…";
    return display;
  } catch {
    return url.substring(0, 45);
  }
}
