"""
PhishGuard AI — Configuration centralisée
Toutes les constantes et paramètres éditables en un seul endroit.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class Config:
    # ─── API ──────────────────────────────────────────────────────────────────
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    # Origins autorisées pour CORS (séparées par des virgules dans l'env)
    allowed_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            o.strip()
            for o in os.getenv(
                "ALLOWED_ORIGINS",
                "chrome-extension://,moz-extension://",
            ).split(",")
            if o.strip()
        )
    )

    # ─── Rate limiting ────────────────────────────────────────────────────────
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
    rate_limit_burst: int = int(os.getenv("RATE_LIMIT_BURST", "10"))

    # ─── Cache ────────────────────────────────────────────────────────────────
    cache_ttl_seconds: int = int(os.getenv("CACHE_TTL", "3600"))  # 1 heure
    cache_max_entries: int = int(os.getenv("CACHE_MAX", "10000"))
    cache_db_path: str = os.getenv("CACHE_DB", "phishguard_cache.db")

    # ─── Analyse ──────────────────────────────────────────────────────────────
    # Taille max du HTML accepté (octets) — évite les abus
    max_html_bytes: int = int(os.getenv("MAX_HTML_BYTES", str(50 * 1024)))
    # Taille max URL
    max_url_length: int = int(os.getenv("MAX_URL_LENGTH", "2048"))

    # ─── Scoring ──────────────────────────────────────────────────────────────
    score_low_threshold: int = 35
    score_medium_threshold: int = 65

    # ─── Réputation ───────────────────────────────────────────────────────────
    # Timeout pour les appels RDAP/SSL (secondes)
    reputation_timeout: float = float(os.getenv("REP_TIMEOUT", "1.5"))
    # Seuil "domaine récent" en jours
    new_domain_days: int = int(os.getenv("NEW_DOMAIN_DAYS", "30"))

    # ─── Typosquatting ────────────────────────────────────────────────────────
    # Distance de Levenshtein max pour considérer une similarité suspecte
    typo_levenshtein_threshold: int = 2
    # Longueur min du domaine cible pour déclencher la vérification
    typo_min_brand_length: int = 4


# Singleton global — importer `settings` partout
settings = Config()


# ─── Marques connues pour typosquatting ──────────────────────────────────────
# Top marques fréquemment usurpées. Garder cette liste courte et pertinente.
KNOWN_BRANDS: FrozenSet[str] = frozenset({
    # Finance
    "paypal", "visa", "mastercard", "americanexpress", "bankofamerica",
    "chase", "wellsfargo", "hsbc", "barclays", "creditagricole",
    "bnpparibas", "societegenerale", "lcl", "caisse-epargne",
    # E-commerce
    "amazon", "ebay", "aliexpress", "cdiscount", "fnac", "darty",
    "leboncoin", "vinted",
    # Tech / Auth
    "google", "microsoft", "apple", "facebook", "instagram", "twitter",
    "linkedin", "netflix", "spotify", "discord", "steam", "twitch",
    "dropbox", "icloud",
    # Crypto
    "binance", "coinbase", "kraken", "metamask", "ledger", "trezor",
    # Services publics FR
    "impots", "ameli", "caf", "pole-emploi", "laposte", "chronopost",
})

# ─── TLDs suspects ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS: FrozenSet[str] = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Gratuits/abusés
    ".xyz", ".top", ".club", ".online", ".site", ".website",
    ".info", ".biz",                      # Historiquement abusés
    ".ru", ".cn", ".pw",                  # Haute fréquence phishing
    ".buzz", ".click", ".link",
})

# ─── Services de raccourcissement d'URL ──────────────────────────────────────
URL_SHORTENERS: FrozenSet[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy",
})

# ─── Mots-clés phishing par catégorie ────────────────────────────────────────
PHISHING_KEYWORDS: dict[str, list[str]] = {
    "authentication": [
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "validate", "authenticate",
    ],
    "urgency": [
        "urgent", "suspended", "blocked", "limited", "expire", "warning",
        "alert", "immediate", "critical",
    ],
    "crypto_scam": [
        "airdrop", "giveaway", "doubler", "free-bitcoin", "free-eth",
        "crypto-bonus", "wallet-connect", "claim-reward",
    ],
    "fake_support": [
        "microsoft-support", "apple-support", "helpdesk", "tech-support",
        "customer-care", "assistance-technique",
    ],
    "banking": [
        "banking", "payment", "invoice", "refund", "transaction",
        "virement", "paiement",
    ],
}

# ─── Table homoglyphes Unicode → ASCII ───────────────────────────────────────
# Caractères visuellement similaires utilisés pour tromper
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillique
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ԛ": "q",
    # Latin étendu
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u",
    "ñ": "n", "ç": "c",
    # Chiffres → lettres
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    # Ligatures
    "ﬁ": "fi", "ﬂ": "fl", "ﬀ": "ff",
}
