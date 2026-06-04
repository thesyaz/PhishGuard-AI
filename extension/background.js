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
/**
 * PhishGuard AI — Background Service Worker V2 (CLEAN)
 */

"use strict";

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

const API_BASE_URL = "https://phishguard-ai-p0qo.onrender.com";
const CACHE_DURATION_MS = 5 * 60 * 1000;
const CACHE_MAX_SIZE = 100;
const FETCH_TIMEOUT_MS = 8000;
const MAX_HTML_LENGTH = 30000;

const analysisCache = new Map();

// ---------------------------------------------------------------------------
// TRUSTED DOMAINS
// ---------------------------------------------------------------------------

const TRUSTED_DOMAINS = new Set([
  "google.com","google.fr","youtube.com","microsoft.com","apple.com",
  "amazon.com","facebook.com","instagram.com","whatsapp.com",
  "github.com","gitlab.com","stackoverflow.com",
  "openai.com","anthropic.com","claude.ai",
  "paypal.com","stripe.com",
  "wikipedia.org","reddit.com","linkedin.com"
]);

const URL_SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd"
]);

const SUSPICIOUS_TLDS = new Set([
  ".tk",".ml",".ga",".cf",".xyz",".top",".click",".icu"
]);

const KNOWN_BRANDS = ["paypal","google","apple","microsoft","amazon"];

// ---------------------------------------------------------------------------
// UTILS
// ---------------------------------------------------------------------------

function isIgnoredUrl(url) {
  return !url || url.startsWith("chrome://") || url.startsWith("chrome-extension://");
}

function getRootDomain(hostname) {
  const parts = hostname.replace(/^www\./, "").split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : hostname;
}

function isTrustedDomain(hostname) {
  const clean = hostname.replace(/^www\./, "").toLowerCase();
  return TRUSTED_DOMAINS.has(clean) || TRUSTED_DOMAINS.has(getRootDomain(clean));
}

async function fetchWithTimeout(url, options = {}, timeout = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}

// ---------------------------------------------------------------------------
// HEURISTICS (FAST LOCAL ENGINE)
// ---------------------------------------------------------------------------

function runLocalHeuristics(url) {
  let score = 0;
  const reasons = [];

  let parsed;
  try { parsed = new URL(url); } catch { return { score: 0, reasons: [] }; }

  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname.toLowerCase();
  const full = url.toLowerCase();
  const root = getRootDomain(host);

  if (isTrustedDomain(host)) {
    return { score: 0, reasons: ["Trusted domain"] };
  }

  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    score += 25;
    reasons.push("IP address used instead of domain");
  }

  if (URL_SHORTENERS.has(host) || URL_SHORTENERS.has(root)) {
    score += 20;
    reasons.push("URL shortener detected");
  }

  const tld = host.match(/\.[^.]+$/)?.[0];
  if (tld && SUSPICIOUS_TLDS.has(tld)) {
    score += 15;
    reasons.push(`Suspicious TLD ${tld}`);
  }

  if (url.includes("@")) {
    score += 20;
    reasons.push("URL contains @ trick");
  }

  const sub = host.split(".").length - 2;
  if (sub > 3) {
    score += 15;
    reasons.push("Too many subdomains");
  }

  if (parsed.protocol === "http:") {
    score += 10;
    reasons.push("No HTTPS");
  }

  if (host !== host.normalize("NFC")) {
    score += 15;
    reasons.push("Unicode domain suspicious");
  }

  const found = KNOWN_BRANDS.filter(b => full.includes(b));
  if (found.length) {
    score += 20;
    reasons.push("Brand impersonation: " + found[0]);
  }

  if (url.length > 100) {
    score += 10;
    reasons.push("Very long URL");
  }

  if (path.includes("//")) {
    score += 10;
    reasons.push("Double slash in path");
  }

  return { score: Math.min(100, score), reasons };
}

// ---------------------------------------------------------------------------
// BADGE
// ---------------------------------------------------------------------------

async function updateBadge(tabId, risk, score) {
  const cfg = {
    HIGH: { text: "!", color: "#EF4444" },
    MEDIUM: { text: "?", color: "#F59E0B" },
    LOW: { text: "✓", color: "#10B981" }
  }[risk] || { text: "✓", color: "#10B981" };

  try {
    chrome.action.setBadgeText({ tabId, text: cfg.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
  } catch {}
}

async function resetBadge(tabId) {
  try {
    chrome.action.setBadgeText({ tabId, text: "" });
  } catch {}
}

// ---------------------------------------------------------------------------
// CACHE
// ---------------------------------------------------------------------------

function cacheResult(url, result) {
  analysisCache.set(url, { result, timestamp: Date.now() });
  if (analysisCache.size > CACHE_MAX_SIZE) {
    const first = analysisCache.keys().next().value;
    if (first) analysisCache.delete(first);
  }
}

// ---------------------------------------------------------------------------
// BACKEND
// ---------------------------------------------------------------------------

async function callBackend(url, title, html) {
  const res = await fetchWithTimeout(`${API_BASE_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url,
      title: title || null,
      html_content: html ? html.slice(0, MAX_HTML_LENGTH) : null
    })
  });

  if (!res.ok) throw new Error("Backend error");
  return res.json();
}

// ---------------------------------------------------------------------------
// MAIN PIPELINE
// ---------------------------------------------------------------------------

async function analyzeTab(tabId, url, title) {
  if (isIgnoredUrl(url)) return resetBadge(tabId);

  const cached = analysisCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION_MS) {
    return updateBadge(tabId, cached.result.risk, cached.result.score);
  }

  let parsed;
  try { parsed = new URL(url); } catch { return; }

  const host = parsed.hostname.toLowerCase();

  // TRUSTED FAST EXIT
  if (isTrustedDomain(host)) {
    const result = {
      url,
      score: 0,
      risk: "LOW",
      reasons: ["Trusted domain"],
      source: "trusted"
    };

    cacheResult(url, result);
    await updateBadge(tabId, "LOW", 0);
    return;
  }

  const local = runLocalHeuristics(url);

  if (local.score < 15) {
    const result = { url, score: local.score, risk: "LOW", reasons: local.reasons };
    cacheResult(url, result);
    return updateBadge(tabId, "LOW", local.score);
  }

  if (local.score >= 80) {
    const result = { url, score: local.score, risk: "HIGH", reasons: local.reasons };
    cacheResult(url, result);
    updateBadge(tabId, "HIGH", local.score);
    return;
  }

  try {
    const html = await extractHTML(tabId);
    const backend = await callBackend(url, title, html);

    cacheResult(url, backend);
    updateBadge(tabId, backend.risk, backend.score);
  } catch {
    const risk = local.score > 60 ? "HIGH" : "MEDIUM";
    const result = { url, score: local.score, risk, reasons: local.reasons };
    cacheResult(url, result);
    updateBadge(tabId, risk, local.score);
  }
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

async function extractHTML(tabId) {
  try {
    const res = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => document.documentElement.outerHTML
    });

    return res?.[0]?.result?.slice(0, MAX_HTML_LENGTH) || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// EVENTS
// ---------------------------------------------------------------------------

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url) {
    analyzeTab(tabId, tab.url, tab.title);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab?.url) analyzeTab(tabId, tab.url, tab.title);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "ANALYZE_NOW") {
    analyzeTab(msg.tabId, msg.url, msg.title).then(() => {
      const cached = analysisCache.get(msg.url);
      sendResponse({ success: true, result: cached?.result || null });
    });
    return true;
  }

  if (msg.type === "GET_CACHED_RESULT") {
    const cached = analysisCache.get(msg.url);
    sendResponse({ result: cached?.result || null });
  }
});
