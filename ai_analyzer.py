"""
PhishGuard AI - Module d'analyse par Intelligence Artificielle

Supporte trois modes :
  - "openai"   : utilise l'API OpenAI (nécessite OPENAI_API_KEY)
  - "ollama"   : utilise un modèle local via Ollama (nécessite Ollama en local)
  - "disabled" : mode désactivé, retourne None

Configuration via variables d'environnement :
  AI_MODE        = openai | ollama | disabled   (défaut : disabled)
  OPENAI_API_KEY = sk-...
  OPENAI_MODEL   = gpt-4o-mini                  (défaut : gpt-4o-mini)
  OLLAMA_HOST    = http://localhost:11434        (défaut)
  OLLAMA_MODEL   = llama3                        (défaut : llama3)
"""

import os
import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger("phishguard.ai")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AI_MODE: str = os.getenv("AI_MODE", "disabled").lower()
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")

# Timeout pour les appels IA (secondes)
# Augmenté à 8s : l'IA est appelée de façon non-bloquante,
# si elle dépasse ce délai on renvoie quand même le résultat heuristique.
AI_TIMEOUT = 8


# ---------------------------------------------------------------------------
# Prompt système commun
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """Tu es un expert en cybersécurité spécialisé dans la détection de phishing.
Ton rôle est d'analyser les informations fournies sur une page web et de produire :
1. Un résumé clair et concis (2-3 phrases maximum) expliquant pourquoi cette page est ou n'est pas suspecte.
2. Une explication adaptée à un utilisateur non-technique.
3. Des recommandations pratiques.

Réponds toujours en français. Sois factuel, bienveillant et non alarmiste.
Ne dépasse pas 150 mots au total.
"""

def _build_user_prompt(
    url: str,
    title: Optional[str],
    heuristic_reasons: list[str],
    score: int,
) -> str:
    """Construit le prompt utilisateur pour l'IA."""
    reasons_text = "\n".join(f"- {r}" for r in heuristic_reasons) if heuristic_reasons else "Aucun indicateur heuristique déclenché."
    return f"""Analyse de sécurité pour :
URL : {url}
Titre de la page : {title or 'Non disponible'}
Score de risque calculé : {score}/100
Indicateurs heuristiques détectés :
{reasons_text}

Fournis un résumé du risque pour cet utilisateur."""


# ---------------------------------------------------------------------------
# Fonctions d'appel aux différents backends IA
# ---------------------------------------------------------------------------

async def _call_openai(prompt: str) -> Optional[str]:
    """Appel à l'API OpenAI."""
    if not OPENAI_API_KEY:
        logger.warning("OPENAI_API_KEY non définie. Mode OpenAI désactivé.")
        return None

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 200,
        "temperature": 0.3,
    }

    try:
        async with httpx.AsyncClient(timeout=AI_TIMEOUT) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
    except httpx.HTTPStatusError as e:
        logger.error(f"Erreur OpenAI HTTP {e.response.status_code}: {e.response.text}")
    except Exception as e:
        logger.error(f"Erreur OpenAI : {e}")
    return None


async def _call_ollama(prompt: str) -> Optional[str]:
    """Appel à Ollama (modèle local)."""
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 200},
    }

    try:
        async with httpx.AsyncClient(timeout=AI_TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"].strip()
    except httpx.ConnectError:
        logger.warning(f"Ollama non accessible à {OLLAMA_HOST}. Vérifiez qu'il est démarré.")
    except Exception as e:
        logger.error(f"Erreur Ollama : {e}")
    return None


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

async def get_ai_summary(
    url: str,
    title: Optional[str],
    heuristic_reasons: list[str],
    score: int,
) -> Optional[str]:
    """
    Génère un résumé IA du risque de phishing.

    Args:
        url              : URL de la page analysée
        title            : Titre de la page (peut être None)
        heuristic_reasons: Liste des descriptions des heuristiques déclenchées
        score            : Score heuristique calculé (0-100)

    Returns:
        str résumé IA, ou None si le mode est désactivé ou en cas d'erreur.
    """
    if AI_MODE == "disabled":
        logger.debug("Mode IA désactivé.")
        return None

    prompt = _build_user_prompt(url, title, heuristic_reasons, score)

    if AI_MODE == "openai":
        logger.info("Appel OpenAI pour analyse IA...")
        return await _call_openai(prompt)

    elif AI_MODE == "ollama":
        logger.info(f"Appel Ollama ({OLLAMA_MODEL}) pour analyse IA...")
        return await _call_ollama(prompt)

    else:
        logger.warning(f"Mode IA inconnu : '{AI_MODE}'. Utiliser 'openai', 'ollama' ou 'disabled'.")
        return None


def get_ai_mode() -> str:
    """Retourne le mode IA actuellement configuré."""
    return AI_MODE
