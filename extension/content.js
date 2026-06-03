/**
 * PhishGuard AI - Content Script
 *
 * Injecté dans chaque page web. Responsable de :
 *  - Collecter des métadonnées de la page (titre, formulaires, iframes, etc.)
 *  - Répondre aux requêtes du popup/background pour obtenir le HTML de la page
 *  - NE collecte jamais de données personnelles ni de mots de passe
 */

(function () {
  "use strict";

  // Évite la double-injection
  if (window.__phishguardInjected) return;
  window.__phishguardInjected = true;

  /**
   * Collecte des métadonnées de sécurité de la page courante.
   * Aucune donnée personnelle n'est collectée.
   * @returns {Object} Métadonnées anonymisées
   */
  function collectPageMetadata() {
    const forms = document.querySelectorAll("form");
    const passwordFields = document.querySelectorAll("input[type='password']");
    const iframes = document.querySelectorAll("iframe");
    const links = document.querySelectorAll("a[href]");

    // Compte les liens externes (domaine différent)
    const currentHost = window.location.hostname;
    let externalLinksCount = 0;
    links.forEach((link) => {
      try {
        const href = link.getAttribute("href");
        if (href && href.startsWith("http")) {
          const linkHost = new URL(href).hostname;
          if (linkHost !== currentHost) externalLinksCount++;
        }
      } catch (_) {}
    });

    // Détecte les iframes cachées
    let hiddenIframes = 0;
    iframes.forEach((iframe) => {
      const style = window.getComputedStyle(iframe);
      const w = parseInt(iframe.getAttribute("width") || "100");
      const h = parseInt(iframe.getAttribute("height") || "100");
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        w <= 1 ||
        h <= 1
      ) {
        hiddenIframes++;
      }
    });

    return {
      title: document.title,
      url: window.location.href,
      formsCount: forms.length,
      passwordFieldsCount: passwordFields.length,
      iframesCount: iframes.length,
      hiddenIframesCount: hiddenIframes,
      externalLinksCount,
      metaDescription: document.querySelector('meta[name="description"]')?.content || null,
    };
  }

  // Écoute les messages du background/popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_PAGE_METADATA") {
      sendResponse(collectPageMetadata());
      return false;
    }

    if (message.type === "GET_PAGE_HTML") {
      // Retourne le HTML de la page (tronqué pour les performances)
      const html = document.documentElement.outerHTML.substring(0, 50000);
      sendResponse({ html });
      return false;
    }
  });

})();
