"""
PhishGuard AI - Serveur FastAPI principal

Endpoints :
  POST /analyze          → Analyse une URL (+ titre + HTML optionnel)
  GET  /history          → Retourne l'historique des analyses
  GET  /stats            → Statistiques globales
  GET  /health           → Health check
  DELETE /history        → Efface l'historique

Lancement :
  uvicorn main:app --reload --port 8000
"""

import uuid
import logging
from datetime import datetime
from collections import deque
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    HistoryEntry,
    RiskLevel,
    StatsResponse,
)
from analyzer import HeuristicAnalyzer, score_to_risk, get_human_reasons
from ai_analyzer import get_ai_summary, get_ai_mode
from blacklist import get_blacklist_stats, reload_blacklist


# ---------------------------------------------------------------------------
# Configuration du logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("phishguard")


# ---------------------------------------------------------------------------
# Application FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PhishGuard AI",
    description=(
        "API de détection de phishing en temps réel combinant "
        "analyse heuristique et intelligence artificielle."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS : autoriser l'extension Chrome à appeler l'API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Restreindre en production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# État en mémoire (remplacer par une DB en production)
# ---------------------------------------------------------------------------

analyzer = HeuristicAnalyzer()

# Historique des 100 dernières analyses (FIFO)
_history: deque[HistoryEntry] = deque(maxlen=100)

# Compteurs globaux
_stats = {
    "total": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "score_sum": 0.0,
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Système"])
async def health_check():
    """Vérifie que le service est opérationnel."""
    bl_stats = get_blacklist_stats()
    return {
        "status": "ok",
        "version": "1.0.0",
        "ai_mode": get_ai_mode(),
        "blacklist": {
            "loaded": bl_stats["loaded"],
            "total_domains": bl_stats["total_domains"],
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/blacklist/stats", tags=["Blacklist"], summary="Statistiques de la blacklist")
async def blacklist_stats():
    """Retourne les statistiques de la base de données de domaines malveillants."""
    return get_blacklist_stats()


@app.post("/blacklist/reload", tags=["Blacklist"], summary="Recharger la blacklist depuis le fichier")
async def reload_bl():
    """Recharge la blacklist.json depuis le disque (utile après une mise à jour du dataset)."""
    count = reload_blacklist()
    logger.info(f"Blacklist rechargée : {count} domaines.")
    return {"reloaded": True, "total_domains": count}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    tags=["Analyse"],
    summary="Analyser une URL pour détecter le phishing",
)
async def analyze_url(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyse une URL et retourne un score de risque de phishing.

    - **url** : URL complète à analyser (obligatoire)
    - **title** : Titre de la page HTML (optionnel, améliore la détection)
    - **html_content** : Contenu HTML brut (optionnel, active les règles DOM)
    """
    logger.info(f"Analyse demandée pour : {request.url[:100]}")

    # 1. Analyse heuristique
    score, heuristics = analyzer.analyze(
        url=request.url,
        title=request.title,
        html_content=request.html_content,
    )

    # 2. Détermination du niveau de risque
    risk_str = score_to_risk(score)
    risk = RiskLevel(risk_str)

    # 3. Construction des raisons lisibles
    reasons = get_human_reasons(heuristics)
    if not reasons:
        reasons = ["Aucun indicateur de phishing détecté. La page semble légitime."]

    # 4. Analyse IA (asynchrone, non bloquante si désactivée)
    ai_summary: Optional[str] = None
    try:
        ai_summary = await get_ai_summary(
            url=request.url,
            title=request.title,
            heuristic_reasons=reasons,
            score=score,
        )
    except Exception as e:
        logger.warning(f"Analyse IA échouée (non critique) : {e}")

    # 5. Mise à jour de l'historique et des stats
    _update_state(request.url, request.title, score, risk)

    response = AnalyzeResponse(
        url=request.url,
        score=score,
        risk=risk,
        reasons=reasons,
        heuristics=heuristics,
        ai_summary=ai_summary,
        analyzed_at=datetime.utcnow(),
    )

    logger.info(f"Résultat : score={score}, risque={risk_str}")
    return response


@app.get(
    "/history",
    response_model=list[HistoryEntry],
    tags=["Historique"],
    summary="Récupérer l'historique des analyses",
)
async def get_history(limit: int = 20) -> list[HistoryEntry]:
    """
    Retourne les **limit** dernières analyses effectuées (max 100).
    """
    limit = min(limit, 100)
    return list(_history)[-limit:][::-1]  # Plus récentes en premier


@app.get(
    "/stats",
    response_model=StatsResponse,
    tags=["Historique"],
    summary="Obtenir les statistiques globales",
)
async def get_stats() -> StatsResponse:
    """Retourne les statistiques agrégées de toutes les analyses."""
    total = _stats["total"]
    avg = round(_stats["score_sum"] / total, 1) if total > 0 else 0.0

    return StatsResponse(
        total_analyses=total,
        high_risk_count=_stats["high"],
        medium_risk_count=_stats["medium"],
        low_risk_count=_stats["low"],
        average_score=avg,
        recent_history=list(_history)[-10:][::-1],
    )


@app.delete(
    "/history",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Historique"],
    summary="Effacer l'historique des analyses",
)
async def clear_history():
    """Supprime tout l'historique en mémoire et remet les compteurs à zéro."""
    _history.clear()
    _stats.update({"total": 0, "high": 0, "medium": 0, "low": 0, "score_sum": 0.0})
    logger.info("Historique effacé.")


# ---------------------------------------------------------------------------
# Utilitaires internes
# ---------------------------------------------------------------------------

def _update_state(url: str, title: Optional[str], score: int, risk: RiskLevel):
    """Met à jour l'historique et les statistiques en mémoire."""
    entry = HistoryEntry(
        id=str(uuid.uuid4()),
        url=url,
        score=score,
        risk=risk,
        analyzed_at=datetime.utcnow(),
        title=title,
    )
    _history.append(entry)

    _stats["total"] += 1
    _stats["score_sum"] += score
    if risk == RiskLevel.HIGH:
        _stats["high"] += 1
    elif risk == RiskLevel.MEDIUM:
        _stats["medium"] += 1
    else:
        _stats["low"] += 1


# ---------------------------------------------------------------------------
# Démarrage direct
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
