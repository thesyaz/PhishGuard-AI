"""
PhishGuard AI - Modèles de données Pydantic
"""

from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from enum import Enum
from datetime import datetime


class RiskLevel(str, Enum):
    """Niveaux de risque possibles."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AnalyzeRequest(BaseModel):
    """Requête d'analyse d'une URL."""
    url: str = Field(..., description="URL complète de la page à analyser")
    title: Optional[str] = Field(None, description="Titre de la page HTML")
    html_content: Optional[str] = Field(None, description="Contenu HTML de la page (optionnel)")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://secure-login.paypa1.com/verify?token=abc123",
                "title": "PayPal - Verify Your Account",
                "html_content": "<form><input type='password' name='pwd'></form>"
            }
        }


class HeuristicDetail(BaseModel):
    """Détail d'une règle heuristique déclenchée."""
    rule: str = Field(..., description="Nom de la règle")
    score_contribution: int = Field(..., description="Points ajoutés au score")
    description: str = Field(..., description="Explication humaine de la règle")


class AnalyzeResponse(BaseModel):
    """Réponse complète de l'analyse."""
    url: str = Field(..., description="URL analysée")
    score: int = Field(..., ge=0, le=100, description="Score de risque de 0 à 100")
    risk: RiskLevel = Field(..., description="Niveau de risque : LOW, MEDIUM, HIGH")
    reasons: List[str] = Field(..., description="Liste des raisons expliquant le score")
    heuristics: List[HeuristicDetail] = Field(default_factory=list, description="Détail des heuristiques déclenchées")
    ai_summary: Optional[str] = Field(None, description="Résumé généré par l'IA (si activée)")
    analyzed_at: datetime = Field(default_factory=datetime.utcnow, description="Horodatage de l'analyse")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://secure-login.paypa1.com/verify?token=abc123",
                "score": 87,
                "risk": "HIGH",
                "reasons": [
                    "L'URL contient une adresse IP ou un domaine suspect avec homoglyphes (paypa1 ≈ paypal).",
                    "Mots-clés suspects détectés : 'secure', 'verify'.",
                    "Formulaire avec champ mot de passe détecté."
                ],
                "heuristics": [],
                "ai_summary": "Cette page présente plusieurs indicateurs classiques de phishing.",
                "analyzed_at": "2024-01-15T10:30:00Z"
            }
        }


class HistoryEntry(BaseModel):
    """Entrée dans l'historique local des analyses."""
    id: str = Field(..., description="Identifiant unique")
    url: str
    score: int
    risk: RiskLevel
    analyzed_at: datetime
    title: Optional[str] = None


class StatsResponse(BaseModel):
    """Statistiques globales du service."""
    total_analyses: int = Field(..., description="Nombre total d'analyses effectuées")
    high_risk_count: int = Field(..., description="Nombre de sites HIGH RISK détectés")
    medium_risk_count: int = Field(..., description="Nombre de sites MEDIUM RISK détectés")
    low_risk_count: int = Field(..., description="Nombre de sites LOW RISK détectés")
    average_score: float = Field(..., description="Score moyen sur toutes les analyses")
    recent_history: List[HistoryEntry] = Field(default_factory=list, description="10 dernières analyses")

# Ajouter dans models.py

class AIResultResponse(BaseModel):
    key: str
    status: str          # "pending" | "done" | "error"
    ai_summary: Optional[str] = None
    error: Optional[str] = None
