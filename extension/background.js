/**
 * PhishGuard AI - Background Service Worker (Manifest V3)
 *
 * Responsabilités :
 *  - Gérer le badge de l'icône (rouge si risque élevé)
 *  - Écouter les messages du popup et du content script
 *  - Mettre en cache les résultats d'analyse récents
 *  - Effectuer l'analyse automatique lors du changement d'onglet
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_BASE_URL = "https://phishguard-ai-p0qo.onrender.com/";
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minutes
const MAX_HTML_LENGTH = 50_000;           // Limite l'envoi HTML pour éviter les timeouts
const API_TIMEOUT_MS = 15_000;            // Timeout fetch côté extension (15 secondes)

// Cache en mémoire : { [url]: { result, timestamp } }
const analysisCache = new Map();


// ---------------------------------------------------------------------------
// Gestion du badge
// ---------------------------------------------------------------------------

/**
 * Met à jour le badge de l'extension selon le score de risque.
 * @param {number} tabId
 * @param {string} risk - "HIGH" | "MEDIUM" | "LOW"
 * @param {number} score
 */
function updateBadge(tabId, risk, score) {
  const configs = {
    HIGH:   { text: "!", color: "#EF4444" },  // Rouge
    MEDIUM: { text: "?", color: "#F59E0B" },  // Orange
    LOW:    { text: "✓", color: "#10B981" },  // Vert
  };

  const cfg = configs[risk] || configs.LOW;

  chrome.action.setBadgeText({ tabId, text: cfg.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
  chrome.action.setTitle({
    tabId,
    title: `PhishGuard AI — Risque ${risk} (score: ${score}/100)`,
  });
}

/**
 * Remet le badge à son état neutre (onglet en cours de chargement ou non analysé).
 */
function resetBadge(tabId) {
  chrome.action.setBadgeText({ tabId, text: "" });
  chrome.action.setTitle({ tabId, title: "PhishGuard AI — Cliquez pour analyser" });
}


// ---------------------------------------------------------------------------
// Appel API backend
// ---------------------------------------------------------------------------

/**
 * Envoie une requête d'analyse au backend Python.
 * @param {string} url
 * @param {string|null} title
 * @param {string|null} htmlContent
 * @returns {Promise<Object>} Réponse JSON du backend
 */
async function callAnalyzeAPI(url, title, htmlContent) {
  const payload = {
    url,
    title: title || null,
    html_content: htmlContent ? htmlContent.substring(0, MAX_HTML_LENGTH) : null,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  const response = await fetch(`${API_BASE_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: controller.signal,
  });
  clearTimeout(timeoutId);

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API Error ${response.status}: ${errorText}`);
  }

  return response.json();
}


// ---------------------------------------------------------------------------
// Analyse automatique d'un onglet
// ---------------------------------------------------------------------------

/**
 * Analyse l'onglet spécifié et met à jour le badge.
 * Utilise le cache si disponible.
 */
async function analyzeTab(tabId, url, title) {
  // Vérifications préalables
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
    resetBadge(tabId);
    return;
  }

  // Vérification du cache
  const cached = analysisCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION_MS) {
    updateBadge(tabId, cached.result.risk, cached.result.score);
    return;
  }

  try {
    // Récupération du HTML via content script
    let htmlContent = null;
    try {
      const [{ result }] = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => document.documentElement.outerHTML,
      });
      htmlContent = result;
    } catch (_) {
      // Certaines pages ne permettent pas l'injection (extensions, PDF, etc.)
    }

    const analysisResult = await callAnalyzeAPI(url, title, htmlContent);

    // Mise en cache
    analysisCache.set(url, { result: analysisResult, timestamp: Date.now() });

    // Nettoyage du cache si trop grand
    if (analysisCache.size > 50) {
      const firstKey = analysisCache.keys().next().value;
      analysisCache.delete(firstKey);
    }

    // Mise à jour du badge
    updateBadge(tabId, analysisResult.risk, analysisResult.score);

    // Sauvegarde dans le stockage local Chrome pour l'historique de l'extension
    saveToLocalHistory(analysisResult);

  } catch (error) {
    console.warn("[PhishGuard] Analyse échouée :", error.message);
    resetBadge(tabId);
  }
}


// ---------------------------------------------------------------------------
// Historique local Chrome
// ---------------------------------------------------------------------------

/**
 * Sauvegarde un résultat d'analyse dans chrome.storage.local.
 */
async function saveToLocalHistory(result) {
  try {
    const data = await chrome.storage.local.get("phishguard_history");
    const history = data.phishguard_history || [];

    history.unshift({
      url: result.url,
      score: result.score,
      risk: result.risk,
      title: result.title || null,
      analyzed_at: new Date().toISOString(),
    });

    // Garde seulement les 50 dernières entrées
    const trimmed = history.slice(0, 50);
    await chrome.storage.local.set({ phishguard_history: trimmed });
  } catch (e) {
    console.warn("[PhishGuard] Sauvegarde historique échouée :", e);
  }
}


// ---------------------------------------------------------------------------
// Écouteurs d'événements Chrome
// ---------------------------------------------------------------------------

// Analyse automatique au changement d'onglet
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url && tab.status === "complete") {
      analyzeTab(tabId, tab.url, tab.title);
    }
  } catch (_) {}
});

// Analyse à la fin du chargement d'une page
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyzeTab(tabId, tab.url, tab.title);
  }
});

// Réponse aux messages du popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_NOW") {
    const { tabId, url, title } = message;

    // Force une nouvelle analyse (ignore le cache)
    analysisCache.delete(url);

    analyzeTab(tabId, url, title)
      .then(() => {
        const cached = analysisCache.get(url);
        sendResponse({ success: true, result: cached?.result || null });
      })
      .catch((err) => {
        sendResponse({ success: false, error: err.message });
      });

    return true; // Maintient le canal ouvert pour la réponse asynchrone
  }

  if (message.type === "GET_CACHED_RESULT") {
    const cached = analysisCache.get(message.url);
    sendResponse({ result: cached?.result || null });
    return false;
  }

  if (message.type === "GET_API_URL") {
    sendResponse({ url: API_BASE_URL });
    return false;
  }
});

// Initialisation au démarrage du service worker
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard AI] Extension installée et prête.");
});
