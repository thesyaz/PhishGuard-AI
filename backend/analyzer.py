"""
PhishGuard AI - Moteur d'analyse heuristique
Chaque règle contribue à un score de 0 à 100.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from typing import List, Tuple
from bs4 import BeautifulSoup

from models import HeuristicDetail
from blacklist import check_domain


# ---------------------------------------------------------------------------
# Configuration des poids des règles heuristiques
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "banking",
    "account", "signin", "password", "credential", "authenticate",
    "confirm", "validation", "suspended", "unusual", "activity"
]

TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io"}

IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

UNICODE_SUSPICIOUS_PATTERN = re.compile(
    r"[^\x00-\x7F]"  # Caractères non-ASCII dans l'URL
)

# Homoglyphes courants utilisés dans le typosquatting
HOMOGLYPH_PAIRS = [
    ("0", "o"), ("1", "l"), ("1", "i"), ("rn", "m"),
    ("vv", "w"), ("cl", "d"), ("5", "s"), ("3", "e")
]


class HeuristicAnalyzer:
    """
    Analyseur heuristique : évalue une URL + contenu HTML selon un ensemble
    de règles pondérées et retourne un score agrégé ainsi que des explications.
    """

    def __init__(self):
        self._rules: List[Tuple[str, callable, int]] = self._build_rules()

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def analyze(
        self,
        url: str,
        title: str | None = None,
        html_content: str | None = None,
    ) -> Tuple[int, List[HeuristicDetail]]:
        """
        Lance l'analyse complète.

        Returns:
            (score_total, liste_details)
            score_total : entier entre 0 et 100
        """
        triggered: List[HeuristicDetail] = []
        raw_score = 0

        parsed = urlparse(url)
        soup = BeautifulSoup(html_content, "html.parser") if html_content else None

        for rule_name, rule_fn, weight in self._rules:
            try:
                result, description = rule_fn(url, parsed, title, soup)
                if result:
                    detail = HeuristicDetail(
                        rule=rule_name,
                        score_contribution=weight,
                        description=description,
                    )
                    triggered.append(detail)
                    raw_score += weight
            except Exception:
                # Une règle qui plante ne doit pas bloquer l'analyse
                pass

        # Normalisation : on plafonne à 100 avec une courbe logistique douce
        score = self._normalize_score(raw_score)
        return score, triggered

    # ------------------------------------------------------------------
    # Construction des règles
    # ------------------------------------------------------------------

    def _build_rules(self) -> List[Tuple[str, callable, int]]:
        """Retourne la liste (nom, fonction, poids) de toutes les règles."""
        return [
            ("URL_LENGTH",          self._rule_url_length,          10),
            ("SUBDOMAIN_COUNT",     self._rule_subdomain_count,     15),
            ("IP_IN_URL",           self._rule_ip_in_url,           25),
            ("UNICODE_SUSPICIOUS",  self._rule_unicode_suspicious,  20),
            ("HOMOGLYPH",           self._rule_homoglyph,           20),
            ("PHISHING_KEYWORDS",   self._rule_phishing_keywords,   15),
            ("HTTPS_MISSING",       self._rule_https_missing,       10),
            ("AT_SYMBOL_IN_URL",    self._rule_at_symbol,           20),
            ("DOUBLE_SLASH_REDIRECT", self._rule_double_slash,      15),
            ("PASSWORD_FORM",       self._rule_password_form,       20),
            ("HIDDEN_IFRAME",       self._rule_hidden_iframe,       20),
            ("EXTERNAL_LINKS_HIGH", self._rule_external_links,      10),
            ("SUSPICIOUS_PORT",     self._rule_suspicious_port,     15),
            ("DATA_URI",            self._rule_data_uri,            20),
            ("TITLE_MISMATCH",      self._rule_title_mismatch,      10),
            ("BLACKLIST_MATCH",     self._rule_blacklist_match,     60),
        ]

    # ------------------------------------------------------------------
    # Règles individuelles
    # Signature : (url, parsed, title, soup) -> (bool_triggered, str_reason)
    # ------------------------------------------------------------------

    def _rule_url_length(self, url, parsed, title, soup):
        """URL anormalement longue (> 75 caractères)."""
        if len(url) > 75:
            return True, f"URL très longue ({len(url)} caractères). Les URL légitimes sont rarement aussi longues."
        return False, ""

    def _rule_subdomain_count(self, url, parsed, title, soup):
        """Trop de sous-domaines (> 3 niveaux)."""
        host = parsed.hostname or ""
        parts = host.split(".")
        subdomain_count = len(parts) - 2  # On exclut domaine + TLD
        if subdomain_count > 2:
            return True, f"Nombre élevé de sous-domaines ({subdomain_count}). Technique courante pour masquer le vrai domaine."
        return False, ""

    def _rule_ip_in_url(self, url, parsed, title, soup):
        """Adresse IP utilisée à la place d'un nom de domaine."""
        host = parsed.hostname or ""
        if IP_PATTERN.match(host):
            return True, f"L'URL utilise une adresse IP ({host}) au lieu d'un nom de domaine. Indicateur fort de phishing."
        return False, ""

    def _rule_unicode_suspicious(self, url, parsed, title, soup):
        """Caractères Unicode non-ASCII dans l'URL (attaque IDN homograph)."""
        host = parsed.hostname or ""
        if UNICODE_SUSPICIOUS_PATTERN.search(host):
            return True, "Caractères Unicode suspects dans le domaine. Technique d'usurpation d'identité visuelle (attaque homographe IDN)."
        return False, ""

    def _rule_homoglyph(self, url, parsed, title, soup):
        """Détection de substitution de caractères similaires visuellement."""
        host = (parsed.hostname or "").lower()
        for legit, fake in HOMOGLYPH_PAIRS:
            if fake in host:
                # Vérifie si ce caractère pourrait être une substitution
                test = host.replace(fake, legit)
                if test != host and len(test) <= len(host):
                    return True, f"Possible substitution de caractères similaires dans le domaine ('{fake}' → '{legit}'). Technique de typosquatting."
        return False, ""

    def _rule_phishing_keywords(self, url, parsed, title, soup):
        """Mots-clés associés au phishing dans l'URL ou le titre."""
        text_to_check = (url + " " + (title or "")).lower()
        found = [kw for kw in PHISHING_KEYWORDS if kw in text_to_check]
        if found:
            return True, f"Mots-clés suspects détectés : {', '.join(found[:5])}. Ces termes sont fréquemment utilisés dans les pages de phishing."
        return False, ""

    def _rule_https_missing(self, url, parsed, title, soup):
        """Absence du protocole HTTPS."""
        if parsed.scheme and parsed.scheme.lower() != "https":
            return True, "La page n'utilise pas HTTPS. Les sites légitimes utilisent presque toujours le chiffrement."
        return False, ""

    def _rule_at_symbol(self, url, parsed, title, soup):
        """Symbole @ dans l'URL (permet de masquer le vrai domaine)."""
        if "@" in url:
            return True, "Le symbole '@' est présent dans l'URL. Technique pour rediriger vers un domaine malveillant tout en affichant un domaine légitime."
        return False, ""

    def _rule_double_slash(self, url, parsed, title, soup):
        """Double slash dans le chemin (redirection masquée)."""
        path = parsed.path or ""
        if "//" in path:
            return True, "Double slash dans le chemin de l'URL, pouvant indiquer une tentative de redirection déguisée."
        return False, ""

    def _rule_password_form(self, url, parsed, title, soup):
        """Formulaire contenant un champ de type 'password'."""
        if soup:
            pwd_inputs = soup.find_all("input", {"type": re.compile(r"password", re.I)})
            if pwd_inputs:
                return True, f"{len(pwd_inputs)} champ(s) de mot de passe détecté(s) dans le formulaire. Risque élevé de vol de credentials."
        return False, ""

    def _rule_hidden_iframe(self, url, parsed, title, soup):
        """Iframes cachées (invisible ou hors écran)."""
        if soup:
            iframes = soup.find_all("iframe")
            hidden = []
            for iframe in iframes:
                style = iframe.get("style", "")
                width = iframe.get("width", "")
                height = iframe.get("height", "")
                if (
                    "display:none" in style.replace(" ", "")
                    or "visibility:hidden" in style.replace(" ", "")
                    or width in ("0", "1")
                    or height in ("0", "1")
                ):
                    hidden.append(iframe)
            if hidden:
                return True, f"{len(hidden)} iframe(s) cachée(s) détectée(s). Technique utilisée pour le clickjacking ou le vol de données."
        return False, ""

    def _rule_external_links(self, url, parsed, title, soup):
        """Nombre excessif de liens externes (> 20)."""
        if soup:
            base_domain = parsed.hostname or ""
            links = soup.find_all("a", href=True)
            external = [
                a for a in links
                if a["href"].startswith("http")
                and base_domain not in a["href"]
            ]
            if len(external) > 20:
                return True, f"{len(external)} liens externes détectés. Peut indiquer une page de distribution de trafic malveillant."
        return False, ""

    def _rule_suspicious_port(self, url, parsed, title, soup):
        """Port non standard utilisé dans l'URL."""
        port = parsed.port
        if port and port not in (80, 443, 8080, 8443):
            return True, f"Port inhabituel détecté ({port}). Les sites légitimes utilisent rarement des ports non standards."
        return False, ""

    def _rule_data_uri(self, url, parsed, title, soup):
        """Présence d'un data URI dans l'URL (rare, souvent malveillant)."""
        if url.startswith("data:"):
            return True, "L'URL est un data URI. Technique avancée d'obfuscation de phishing."
        return False, ""

    def _rule_title_mismatch(self, url, parsed, title, soup):
        """Le titre de la page mentionne une marque absente du domaine."""
        KNOWN_BRANDS = [
            "paypal", "google", "microsoft", "apple", "amazon",
            "facebook", "netflix", "instagram", "twitter", "linkedin",
            "bank", "hsbc", "bnp", "crédit agricole", "société générale"
        ]
        if title and parsed.hostname:
            title_lower = title.lower()
            host_lower = parsed.hostname.lower()
            for brand in KNOWN_BRANDS:
                if brand in title_lower and brand not in host_lower:
                    return True, f"La page prétend appartenir à '{brand}' mais ce nom est absent du domaine réel. Usurpation d'identité probable."
        return False, ""

    def _rule_blacklist_match(self, url, parsed, title, soup):
        """Domaine présent dans la blacklist de 62 000+ sites malveillants connus."""
        result = check_domain(url)
        if result["found"]:
            threat_type = result["type"]
            match_type  = result["match_type"]
            domain      = result["domain"]

            type_labels = {
                "phishing": "phishing (vol de données)",
                "malware":  "distribution de malware",
            }
            label = type_labels.get(threat_type, threat_type)

            if match_type == "subdomain":
                parent = result.get("matched_parent", domain)
                msg = (
                    f"⚠️ Domaine parent '{parent}' répertorié dans la base de données "
                    f"de {label} (62 000+ sites connus). Ce sous-domaine en hérite le risque."
                )
            else:
                msg = (
                    f"⚠️ Domaine '{domain}' directement répertorié dans la base de données "
                    f"de {label} (62 000+ sites malveillants connus)."
                )
            return True, msg
        return False, ""

    # ------------------------------------------------------------------
    # Utilitaires
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_score(raw: int) -> int:
        """
        Convertit un score brut (somme des poids) en score 0-100.
        Utilise une courbe logistique pour éviter les valeurs extrêmes abruptes.
        """
        if raw <= 0:
            return 0
        # Logistic : score = 100 / (1 + e^(-k*(x - midpoint)))
        # Calibré pour que raw=30 → ~50, raw=60 → ~85, raw=100 → ~97
        k = 0.07
        midpoint = 30
        logistic = 100 / (1 + math.exp(-k * (raw - midpoint)))
        return min(100, round(logistic))


def score_to_risk(score: int) -> str:
    """Convertit un score numérique en niveau de risque textuel."""
    if score >= 65:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    else:
        return "LOW"


def get_human_reasons(heuristics: List[HeuristicDetail]) -> List[str]:
    """Extrait la liste des descriptions humaines depuis les heuristiques déclenchées."""
    return [h.description for h in heuristics]
