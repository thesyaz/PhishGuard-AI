"""
PhishGuard AI — Règles heuristiques URL et domaine.

Couvre :
- Longueur URL
- IP dans URL
- Sous-domaines excessifs
- Symbole @ dans URL
- Port non standard
- TLD suspects
- Typosquatting (Levenshtein)
- Homoglyphes Unicode
- URL Shorteners
- Caractères suspects
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from config import HOMOGLYPH_MAP, KNOWN_BRANDS, SUSPICIOUS_TLDS, URL_SHORTENERS, settings
from heuristics.base import (
    HeuristicRule,
    RuleContext,
    count_subdomains,
    extract_domain_without_tld,
    levenshtein_distance,
    normalize_homoglyphs,
)


class URLLengthRule(HeuristicRule):
    """URL anormalement longue — souvent utilisée pour masquer la vraie destination."""

    rule_id = "url_length"
    category = "url"
    max_score = 10
    description = "URL dépassant 75 caractères"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        length = len(ctx.url)
        if length > 100:
            return True, self.max_score, (
                f"L'URL est très longue ({length} caractères). "
                "Les sites légitimes utilisent rarement des URLs aussi complexes."
            )
        if length > 75:
            return True, self.max_score // 2, (
                f"L'URL est longue ({length} caractères), ce qui peut indiquer une tentative de dissimulation."
            )
        return False, 0, ""


class IPInURLRule(HeuristicRule):
    """Adresse IP à la place d'un nom de domaine — signe fort de phishing."""

    rule_id = "ip_in_url"
    category = "url"
    max_score = 30
    description = "Adresse IP au lieu d'un nom de domaine"
    _ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        host = ctx.full_host.split(":")[0]
        if self._ipv4.match(host):
            return True, self.max_score, (
                f"Le site utilise une adresse IP ({host}) au lieu d'un nom de domaine. "
                "Les sites légitimes n'agissent jamais ainsi."
            )
        return False, 0, ""


class SubdomainCountRule(HeuristicRule):
    """Trop de sous-domaines — technique pour imiter des URLs légitimes."""

    rule_id = "subdomain_count"
    category = "url"
    max_score = 20
    description = "Nombre excessif de sous-domaines"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        count = count_subdomains(ctx.full_host)
        if count >= 4:
            return True, self.max_score, (
                f"L'URL contient {count} niveaux de sous-domaines "
                "(ex: secure.login.verify.paypal.site.com). "
                "Technique utilisée pour tromper visuellement l'utilisateur."
            )
        if count >= 3:
            return True, self.max_score // 2, (
                f"L'URL contient {count} sous-domaines, ce qui est inhabituel pour un site légitime."
            )
        return False, 0, ""


class AtSymbolRule(HeuristicRule):
    """Symbole @ dans l'URL — cache la vraie destination."""

    rule_id = "at_symbol"
    category = "url"
    max_score = 25
    description = "Symbole @ dans l'URL"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        if "@" in ctx.url:
            return True, self.max_score, (
                "L'URL contient un symbole '@'. Tout ce qui précède ce symbole "
                "est ignoré par le navigateur, ce qui permet de masquer la vraie adresse."
            )
        return False, 0, ""


class SuspiciousPortRule(HeuristicRule):
    """Port non standard dans l'URL."""

    rule_id = "suspicious_port"
    category = "url"
    max_score = 15
    description = "Port non standard"
    _standard_ports = {80, 443, 8080, 8443, 3000, 5000}

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        port_str = ctx.parsed_url.port
        if port_str and port_str not in self._standard_ports:
            return True, self.max_score, (
                f"Le site utilise le port {port_str}, inhabituel pour un site web normal. "
                "Les banques et services légitimes utilisent toujours les ports standards."
            )
        return False, 0, ""


class HTTPSMissingRule(HeuristicRule):
    """Absence de HTTPS — connexion non chiffrée."""

    rule_id = "https_missing"
    category = "url"
    max_score = 10
    description = "Absence de HTTPS"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        if ctx.parsed_url.scheme == "http":
            return True, self.max_score, (
                "Le site n'utilise pas HTTPS. Votre connexion n'est pas chiffrée "
                "et vos données peuvent être interceptées."
            )
        return False, 0, ""


class DataURIRule(HeuristicRule):
    """URL de type data: — technique de contournement."""

    rule_id = "data_uri"
    category = "url"
    max_score = 25
    description = "URL de type data:"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        if ctx.url.lower().startswith("data:"):
            return True, self.max_score, (
                "L'URL utilise un schéma 'data:' pour incorporer du contenu directement. "
                "Technique utilisée pour contourner les filtres de sécurité."
            )
        return False, 0, ""


class DoubleSlashRedirectRule(HeuristicRule):
    """Double slash dans le chemin — technique de redirection."""

    rule_id = "double_slash_redirect"
    category = "url"
    max_score = 15
    description = "Double slash dans le chemin URL"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        path = ctx.path
        if "//" in path:
            return True, self.max_score, (
                "L'URL contient un double slash (//) dans son chemin. "
                "Technique souvent utilisée pour des redirections malveillantes."
            )
        return False, 0, ""


# ─── Règles de domaine ────────────────────────────────────────────────────────


class SuspiciousTLDRule(HeuristicRule):
    """Extension de domaine statistiquement associée au phishing."""

    rule_id = "suspicious_tld"
    category = "domain"
    max_score = 20
    description = "Extension de domaine suspecte (.tk, .ml, .xyz...)"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        for tld in SUSPICIOUS_TLDS:
            if ctx.domain.endswith(tld):
                return True, self.max_score, (
                    f"L'extension de domaine '{tld}' est fréquemment utilisée "
                    "pour créer des sites frauduleux car elle est bon marché ou gratuite."
                )
        return False, 0, ""


class URLShortenerRule(HeuristicRule):
    """Service de raccourcissement d'URL — cache la vraie destination."""

    rule_id = "url_shortener"
    category = "domain"
    max_score = 20
    description = "Service de raccourcissement d'URL détecté"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        host = ctx.full_host.lower()
        for shortener in URL_SHORTENERS:
            if host == shortener or host.endswith(f".{shortener}"):
                return True, self.max_score, (
                    f"L'URL passe par un service de raccourcissement ({shortener}). "
                    "La vraie destination est masquée — soyez très prudent."
                )
        return False, 0, ""


class TyposquattingRule(HeuristicRule):
    """
    Détection de typosquatting par distance de Levenshtein.
    Compare le domaine principal avec les 500+ marques connues.
    Ex: 'paypa1.com', 'arnazon.com', 'micosoft.com'
    """

    rule_id = "typosquatting"
    category = "domain"
    max_score = 35
    description = "Nom de domaine similaire à une marque connue (typosquatting)"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        domain_name = extract_domain_without_tld(ctx.domain)
        if len(domain_name) < settings.typo_min_brand_length:
            return False, 0, ""

        # Ne pas signaler si c'est exactement la marque
        if domain_name in KNOWN_BRANDS:
            return False, 0, ""

        threshold = settings.typo_levenshtein_threshold
        for brand in KNOWN_BRANDS:
            if len(brand) < settings.typo_min_brand_length:
                continue
            # Optimisation : écarter rapidement si différence de longueur trop grande
            if abs(len(domain_name) - len(brand)) > threshold:
                continue
            dist = levenshtein_distance(domain_name, brand)
            if 0 < dist <= threshold:
                return True, self.max_score, (
                    f"Le domaine '{ctx.domain}' ressemble fortement à '{brand}.com' "
                    f"(seulement {dist} caractère(s) de différence). "
                    "Il s'agit probablement d'une usurpation d'identité de cette marque."
                )
        return False, 0, ""


class HomoglyphRule(HeuristicRule):
    """
    Détection d'attaques homoglyphes.
    Ex: 'pаypal.com' avec un 'а' cyrillique (visuellement identique à 'a' latin)
    """

    rule_id = "homoglyph"
    category = "domain"
    max_score = 30
    description = "Caractères Unicode visuellement similaires aux marques connues"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        domain_name = extract_domain_without_tld(ctx.domain)

        # Si le domaine contient des caractères non-ASCII
        try:
            domain_name.encode("ascii")
            has_unicode = False
        except UnicodeEncodeError:
            has_unicode = True

        if not has_unicode:
            return False, 0, ""

        # Normaliser les homoglyphes
        normalized = normalize_homoglyphs(domain_name, HOMOGLYPH_MAP)

        if normalized == domain_name:
            return False, 0, ""

        # Vérifier si normalisé = marque connue
        if normalized in KNOWN_BRANDS:
            return True, self.max_score, (
                f"Le domaine utilise des caractères Unicode spéciaux qui ressemblent "
                f"à '{normalized}.com'. C'est une technique d'usurpation d'identité "
                "très sophistiquée, invisible à l'œil nu."
            )

        return False, 0, ""


class BrandInSubdomainRule(HeuristicRule):
    """
    Marque connue dans le sous-domaine mais pas dans le domaine principal.
    Ex: 'paypal.secure-login.phishing.com' — paypal est dans le sous-domaine
    """

    rule_id = "brand_in_subdomain"
    category = "domain"
    max_score = 25
    description = "Marque connue dans le sous-domaine uniquement"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        if not ctx.subdomain:
            return False, 0, ""

        domain_name = extract_domain_without_tld(ctx.domain)

        for brand in KNOWN_BRANDS:
            # La marque est dans le sous-domaine mais PAS dans le domaine principal
            if brand in ctx.subdomain and brand not in domain_name:
                return True, self.max_score, (
                    f"Le sous-domaine contient le nom '{brand}' mais "
                    f"le vrai domaine est '{ctx.domain}'. "
                    "Technique classique pour faire croire que le site appartient à cette marque."
                )
        return False, 0, ""


class TitleMismatchRule(HeuristicRule):
    """
    Marque connue dans le titre de la page mais absente du domaine.
    Ex: titre 'PayPal - Connectez-vous' mais domaine 'secure-account-verify.com'
    """

    rule_id = "title_mismatch"
    category = "domain"
    max_score = 20
    description = "Marque connue dans le titre mais absente du domaine"

    def evaluate(self, ctx: RuleContext) -> tuple[bool, int, str]:
        if not ctx.title:
            return False, 0, ""

        domain_name = extract_domain_without_tld(ctx.domain)

        for brand in KNOWN_BRANDS:
            if brand in ctx.title and brand not in domain_name:
                return True, self.max_score, (
                    f"La page prétend appartenir à '{brand}' (visible dans son titre) "
                    f"mais le vrai domaine est '{ctx.domain}'. "
                    "Usurpation d'identité probable."
                )
        return False, 0, ""
