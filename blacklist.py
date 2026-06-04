"""
PhishGuard AI - Module de vérification de blacklist

Charge la blacklist générée depuis le dataset malicious_phish.csv
(62 000+ domaines phishing/malware connus).

Sources :
  - blacklist.json : généré depuis malicious_phish.csv (phishing + malware)
  - Peut être rechargé à chaud via reload_blacklist()

Usage :
  from blacklist import check_domain, get_blacklist_stats
  result = check_domain("halkbankparaf-para.com")
  # → {"found": True, "type": "phishing", "domain": "halkbankparaf-para.com"}
"""

import json
import logging
import os
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger("phishguard.blacklist")

# Chemin vers la blacklist JSON
BLACKLIST_PATH = os.path.join(os.path.dirname(__file__), "blacklist.json")

# Stockage en mémoire : {domain: type}
_blacklist: dict[str, str] = {}
_loaded: bool = False


def _load_blacklist() -> None:
    """Charge la blacklist JSON en mémoire."""
    global _blacklist, _loaded

    if not os.path.exists(BLACKLIST_PATH):
        logger.warning(
            f"Blacklist non trouvée à {BLACKLIST_PATH}. "
            "Lancez generate_blacklist.py pour la générer."
        )
        _blacklist = {}
        _loaded = True
        return

    try:
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            _blacklist = json.load(f)
        _loaded = True
        logger.info(f"Blacklist chargée : {len(_blacklist):,} domaines connus.")
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la blacklist : {e}")
        _blacklist = {}
        _loaded = True


def _ensure_loaded() -> None:
    """Charge la blacklist si ce n'est pas encore fait (lazy loading)."""
    if not _loaded:
        _load_blacklist()


def reload_blacklist() -> int:
    """
    Recharge la blacklist depuis le fichier (utile après une mise à jour).
    Retourne le nombre de domaines chargés.
    """
    global _loaded
    _loaded = False
    _ensure_loaded()
    return len(_blacklist)


def extract_domain(url: str) -> str:
    """
    Extrait le hostname normalisé depuis une URL ou un nom de domaine brut.

    Exemples :
      "https://www.paypal-phish.com/login" → "paypal-phish.com"
      "malicious.example.com"              → "malicious.example.com"
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        # Supprime le préfixe www.
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def check_domain(url: str) -> dict:
    """
    Vérifie si l'URL ou le domaine est dans la blacklist.

    Args:
        url : URL complète ou nom de domaine brut

    Returns:
        dict avec les clés :
          - found       (bool)   : True si le domaine est blacklisté
          - type        (str)    : "phishing" | "malware" | None
          - domain      (str)    : domaine normalisé extrait de l'URL
          - match_type  (str)    : "exact" | "subdomain" | None
    """
    _ensure_loaded()

    domain = extract_domain(url)
    if not domain:
        return {"found": False, "type": None, "domain": domain, "match_type": None}

    # 1. Correspondance exacte
    if domain in _blacklist:
        return {
            "found": True,
            "type": _blacklist[domain],
            "domain": domain,
            "match_type": "exact",
        }

    # 2. Correspondance par sous-domaine
    # Ex: "evil.paypal-phish.com" → vérifie aussi "paypal-phish.com"
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in _blacklist:
            return {
                "found": True,
                "type": _blacklist[parent],
                "domain": domain,
                "match_type": "subdomain",
                "matched_parent": parent,
            }

    return {"found": False, "type": None, "domain": domain, "match_type": None}


def get_blacklist_stats() -> dict:
    """Retourne des statistiques sur la blacklist chargée."""
    _ensure_loaded()

    phishing_count = sum(1 for t in _blacklist.values() if t == "phishing")
    malware_count  = sum(1 for t in _blacklist.values() if t == "malware")

    return {
        "total_domains": len(_blacklist),
        "phishing_domains": phishing_count,
        "malware_domains": malware_count,
        "loaded": _loaded,
        "path": BLACKLIST_PATH,
    }


def is_blacklisted(url: str) -> bool:
    """Raccourci : retourne True si l'URL est blacklistée."""
    return check_domain(url)["found"]
