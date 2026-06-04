/**
 * PhishGuard AI — Background Service Worker (Manifest V3)
 * =========================================================
 * Déployé sur : https://phishguard-ai-p0qo.onrender.com
 *
 * Responsabilités :
 *  - Analyse automatique lors du changement/chargement d'onglet
 *  - Gestion du badge de risque (rouge / orange / vert)
 *  - Cache mémoire des résultats (5 minutes)
 *  - Historique local via chrome.storage.local
 *  - Communication popup ↔ background (GET_CACHED_RESULT, ANALYZE_NOW, GET_API_URL)
 *  - Vérification de santé du backend avant chaque analyse
 *  - Aucun crash du service worker (toutes les erreurs sont interceptées)
 */

"use strict";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** URL de base du backend Render (production). */
const API_BASE_URL = "https://phishguard-ai-p0qo.onrender.com";

/** Durée de validité du cache mémoire : 5 minutes. */
const CACHE_DURATION_MS = 5 * 60 * 1000;

/** Taille maximale du HTML envoyé au backend pour éviter les timeouts. */
const MAX_HTML_LENGTH = 50_000;

/** Timeout réseau pour les appels fetch (millisecondes). */
const FETCH_TIMEOUT_MS = 10_000;

/** Nombre maximum d'entrées dans le cache mémoire. */
const CACHE_MAX_SIZE = 50;

/** Nombre maximum d'entrées dans l'historique local Chrome. */
const HISTORY_MAX_SIZE = 50;

/**
 * Cache mémoire des résultats d'analyse.
 * Clé : URL (string) → Valeur : { result: Object, timestamp: number }
 */
const analysisCache = new Map();

/**
 * Préfixes d'URL à ignorer systématiquement (pages système non analysables).
 */
const IGNORED_URL_PREFIXES = [
  "chrome://",
  "chrome-extension://",
  "edge://",
  "about:",
  "moz-extension://",
];


// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/**
 * Détermine si une URL doit être ignorée (page système, extension, etc.).
 * @param {string|undefined} url
 * @returns {boolean}
 */
function isIgnoredUrl(url) {
  if (!url || typeof url !== "string") return true;
  return IGNORED_URL_PREFIXES.some((prefix) => url.startsWith(prefix));
}

/**
 * Effectue un fetch avec un timeout automatique.
 * Lève une erreur si la réponse dépasse FETCH_TIMEOUT_MS.
 * @param {string} url
 * @param {RequestInit} options
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timerId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timerId);
  }
}

/**
 * Vérifie que l'onglet avec l'identifiant donné existe toujours.
 * @param {number} tabId
 * @returns {Promise<chrome.tabs.Tab|null>} L'objet Tab, ou null si absent.
 */
async function safeGetTab(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return tab;
  } catch (_) {
    // L'onglet a été fermé ou n'existe plus — c'est un cas normal.
    console.log(`[PhishGuard] Onglet ${tabId} introuvable (probablement fermé).`);
    return null;
  }
}

/**
 * Vérifie que le backend est accessible via GET /health.
 * @returns {Promise<boolean>}
 */
async function isBackendHealthy() {
  try {
    const response = await fetchWithTimeout(`${API_BASE_URL}/health`);
    if (response.ok) {
      console.log("[PhishGuard] Backend accessible — santé OK.");
      return true;
    }
    console.warn(`[PhishGuard] Backend inaccessible — statut HTTP ${response.status}.`);
    return false;
  } catch (error) {
    if (error.name === "AbortError") {
      console.warn("[PhishGuard] Backend inaccessible — timeout GET /health.");
    } else {
      console.warn("[PhishGuard] Backend inaccessible — erreur réseau :", error.message);
    }
    return false;
  }
}


// ---------------------------------------------------------------------------
// Gestion du badge
// ---------------------------------------------------------------------------

/**
 * Met à jour le badge de l'extension selon le niveau de risque.
 * Vérifie d'abord que l'onglet existe pour éviter "No tab with id".
 * @param {number} tabId
 * @param {string} risk — "HIGH" | "MEDIUM" | "LOW"
 * @param {number} score — Score de 0 à 100
 */
async function updateBadge(tabId, risk, score) {
  const tab = await safeGetTab(tabId);
  if (!tab) return; // L'onglet a disparu entre-temps

  const configs = {
    HIGH:   { text: "!", color: "#EF4444" }, // Rouge
    MEDIUM: { text: "?", color: "#F59E0B" }, // Orange
    LOW:    { text: "✓", color: "#10B981" }, // Vert
  };

  const cfg = configs[risk] || configs.LOW;

  try {
    chrome.action.setBadgeText({ tabId, text: cfg.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
    chrome.action.setTitle({
      tabId,
      title: `PhishGuard AI — Risque ${risk} (score : ${score}/100)`,
    });
  } catch (error) {
    console.warn(`[PhishGuard] Impossible de mettre à jour le badge de l'onglet ${tabId} :`, error.message);
  }
}

/**
 * Remet le badge à son état neutre (page en chargement ou non analysée).
 * Vérifie d'abord que l'onglet existe.
 * @param {number} tabId
 */
async function resetBadge(tabId) {
  const tab = await safeGetTab(tabId);
  if (!tab) return;

  try {
    chrome.action.setBadgeText({ tabId, text: "" });
    chrome.action.setTitle({ tabId, title: "PhishGuard AI — Cliquez pour analyser" });
  } catch (error) {
    console.warn(`[PhishGuard] Impossible de réinitialiser le badge de l'onglet ${tabId} :`, error.message);
  }
}


// ---------------------------------------------------------------------------
// Appel API backend
// ---------------------------------------------------------------------------

/**
 * Envoie une requête POST /analyze au backend Python.
 * @param {string} url — URL de la page à analyser
 * @param {string|null} title — Titre de la page
 * @param {string|null} htmlContent — HTML brut de la page (tronqué)
 * @returns {Promise<Object>} — Réponse JSON du backend
 */
async function callAnalyzeAPI(url, title, htmlContent) {
  const payload = {
    url,
    title: title || null,
    html_content: htmlContent
      ? htmlContent.substring(0, MAX_HTML_LENGTH)
      : null,
  };

  const response = await fetchWithTimeout(`${API_BASE_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "(corps illisible)");
    throw new Error(`API ${response.status}: ${errorText}`);
  }

  return response.json();
}


// ---------------------------------------------------------------------------
// Extraction HTML via content script
// ---------------------------------------------------------------------------

/**
 * Tente d'extraire le HTML de la page via executeScript.
 * Retourne null en cas d'échec (PDF, page protégée, extension, etc.).
 * @param {number} tabId
 * @returns {Promise<string|null>}
 */
async function extractPageHtml(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => document.documentElement.outerHTML,
    });

    // S'assurer que le résultat est valide
    if (Array.isArray(results) && results.length > 0 && results[0].result) {
      return results[0].result;
    }
    return null;
  } catch (error) {
    // Erreurs attendues : page PDF, chrome://, page protégée par CSP, etc.
    console.log(`[PhishGuard] Extraction HTML ignorée pour l'onglet ${tabId} :`, error.message);
    return null;
  }
}


// ---------------------------------------------------------------------------
// Historique local Chrome
// ---------------------------------------------------------------------------

/**
 * Sauvegarde un résultat d'analyse dans chrome.storage.local.
 * Ne lève jamais d'erreur pour ne pas perturber le flux principal.
 * @param {Object} result — Résultat d'analyse du backend
 */
async function saveToLocalHistory(result) {
  try {
    const data = await chrome.storage.local.get("phishguard_history");
    const history = Array.isArray(data.phishguard_history)
      ? data.phishguard_history
      : [];

    history.unshift({
      url: result.url,
      score: result.score,
      risk: result.risk,
      title: result.title || null,
      analyzed_at: new Date().toISOString(),
    });

    // Conservation des HISTORY_MAX_SIZE dernières entrées uniquement
    const trimmed = history.slice(0, HISTORY_MAX_SIZE);
    await chrome.storage.local.set({ phishguard_history: trimmed });
    console.log(`[PhishGuard] Historique mis à jour (${trimmed.length} entrées).`);
  } catch (error) {
    console.warn("[PhishGuard] Sauvegarde historique échouée :", error.message);
  }
}


// ---------------------------------------------------------------------------
// Analyse principale d'un onglet
// ---------------------------------------------------------------------------

/**
 * Analyse l'onglet spécifié et met à jour le badge.
 * - Vérifie que l'onglet existe avant toute opération.
 * - Ignore les URLs système.
 * - Utilise le cache si le résultat est récent.
 * - Vérifie la santé du backend avant d'appeler l'API.
 * - Ne vide jamais un cache valide en cas d'échec.
 * - Ne fait jamais planter le service worker.
 *
 * @param {number} tabId
 * @param {string} url
 * @param {string|null} title
 */
async function analyzeTab(tabId, url, title) {
  // --- Garde-fous URL ---
  if (isIgnoredUrl(url)) {
    await resetBadge(tabId);
    return;
  }

  // --- Vérification que l'onglet existe encore ---
  const tab = await safeGetTab(tabId);
  if (!tab) {
    console.log(`[PhishGuard] Analyse annulée — onglet ${tabId} introuvable.`);
    return;
  }

  // --- Vérification du cache mémoire ---
  const cached = analysisCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION_MS) {
    console.log(`[PhishGuard] Résultat servi depuis le cache pour : ${url}`);
    await updateBadge(tabId, cached.result.risk, cached.result.score);
    return;
  }

  console.log(`[PhishGuard] Début de l'analyse pour l'onglet ${tabId} : ${url}`);

  // --- Vérification de santé du backend ---
  const healthy = await isBackendHealthy();
  if (!healthy) {
    console.warn("[PhishGuard] Analyse abandonnée — backend inaccessible.");
    // Ne pas réinitialiser le badge s'il affichait un résultat en cache valide
    return;
  }

  try {
    // --- Extraction HTML (optionnelle, peut échouer sans conséquence) ---
    const htmlContent = await extractPageHtml(tabId);

    // --- Re-vérification de l'onglet après l'extraction HTML (peut prendre du temps) ---
    const tabStillExists = await safeGetTab(tabId);
    if (!tabStillExists) {
      console.log(`[PhishGuard] Onglet ${tabId} fermé pendant l'extraction HTML — analyse annulée.`);
      return;
    }

    // --- Appel API backend ---
    const analysisResult = await callAnalyzeAPI(url, title, htmlContent);

    // --- Mise en cache du résultat ---
    analysisCache.set(url, { result: analysisResult, timestamp: Date.now() });

    // Nettoyage du cache si la limite de taille est atteinte
    if (analysisCache.size > CACHE_MAX_SIZE) {
      const oldestKey = analysisCache.keys().next().value;
      analysisCache.delete(oldestKey);
      console.log(`[PhishGuard] Cache nettoyé — entrée la plus ancienne supprimée.`);
    }

    console.log(
      `[PhishGuard] Analyse terminée — Risque : ${analysisResult.risk}, Score : ${analysisResult.score}/100`
    );

    // --- Mise à jour du badge ---
    await updateBadge(tabId, analysisResult.risk, analysisResult.score);

    // --- Sauvegarde dans l'historique local Chrome ---
    await saveToLocalHistory(analysisResult);

  } catch (error) {
    // Gestion des différents types d'erreurs sans crash
    if (error.name === "AbortError") {
      console.warn(`[PhishGuard] Timeout réseau lors de l'analyse de : ${url}`);
    } else {
      console.warn(`[PhishGuard] Erreur lors de l'analyse de ${url} :`, error.message);
    }

    // IMPORTANT : ne pas réinitialiser le badge si un résultat en cache existe encore
    const stillCached = analysisCache.get(url);
    if (!stillCached) {
      await resetBadge(tabId);
    } else {
      console.log("[PhishGuard] Cache précédent conservé malgré l'échec.");
    }
  }
}


// ---------------------------------------------------------------------------
// Écouteurs d'événements Chrome
// ---------------------------------------------------------------------------

/**
 * Analyse automatique lors du changement d'onglet actif.
 * On vérifie que la page est entièrement chargée avant d'analyser.
 */
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await safeGetTab(tabId);
    if (!tab) return;

    if (tab.url && tab.status === "complete") {
      console.log(`[PhishGuard] Changement d'onglet détecté — analyse de l'onglet ${tabId}.`);
      await analyzeTab(tabId, tab.url, tab.title);
    } else {
      console.log(`[PhishGuard] Onglet ${tabId} ignoré (statut : ${tab.status}).`);
    }
  } catch (error) {
    // Sécurité ultime : ne jamais laisser planter l'écouteur
    console.warn("[PhishGuard] Erreur dans onActivated :", error.message);
  }
});

/**
 * Analyse lors de la fin du chargement complet d'une page.
 * Déclenché par status === "complete" uniquement.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  try {
    if (changeInfo.status !== "complete") return;
    if (!tab.url) return;

    console.log(`[PhishGuard] Page chargée — analyse de l'onglet ${tabId}.`);
    await analyzeTab(tabId, tab.url, tab.title);
  } catch (error) {
    // Sécurité ultime : ne jamais laisser planter l'écouteur
    console.warn("[PhishGuard] Erreur dans onUpdated :", error.message);
  }
});

/**
 * Gestion des messages envoyés par le popup ou les content scripts.
 *
 * Messages supportés :
 *  - ANALYZE_NOW        : Force une nouvelle analyse (ignore le cache)
 *  - GET_CACHED_RESULT  : Retourne le résultat en cache pour une URL
 *  - GET_API_URL        : Retourne l'URL du backend configuré
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // --- ANALYZE_NOW : Analyse forcée depuis le popup ---
  if (message.type === "ANALYZE_NOW") {
    const { tabId, url, title } = message;

    if (!tabId || !url) {
      sendResponse({ success: false, error: "Paramètres manquants (tabId ou url)." });
      return false;
    }

    // Suppression du cache pour forcer une nouvelle analyse
    analysisCache.delete(url);
    console.log(`[PhishGuard] Analyse forcée par le popup pour l'onglet ${tabId}.`);

    analyzeTab(tabId, url, title)
      .then(() => {
        const cached = analysisCache.get(url);
        sendResponse({ success: true, result: cached?.result || null });
      })
      .catch((error) => {
        console.warn("[PhishGuard] ANALYZE_NOW échoué :", error.message);
        sendResponse({ success: false, error: error.message });
      });

    return true; // Maintient le canal ouvert pour la réponse asynchrone
  }

  // --- GET_CACHED_RESULT : Lecture du cache pour une URL ---
  if (message.type === "GET_CACHED_RESULT") {
    const cached = analysisCache.get(message.url);
    const isValid = cached && Date.now() - cached.timestamp < CACHE_DURATION_MS;
    sendResponse({ result: isValid ? cached.result : null });
    return false;
  }

  // --- GET_API_URL : Lecture de l'URL du backend ---
  if (message.type === "GET_API_URL") {
    sendResponse({ url: API_BASE_URL });
    return false;
  }
});


// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/** Journalisation au démarrage du service worker (installation ou rechargement). */
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard AI] Extension installée et prête.");
  console.log(`[PhishGuard AI] Backend configuré : ${API_BASE_URL}`);
});

console.log("[PhishGuard AI] Service worker démarré.");
