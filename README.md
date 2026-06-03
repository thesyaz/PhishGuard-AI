# 🛡️ PhishGuard AI

**Détection de phishing en temps réel** — Extension Chrome (Manifest V3) + Backend Python FastAPI.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![Chrome MV3](https://img.shields.io/badge/Chrome-Manifest%20V3-yellow)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 📋 Table des matières

1. [Présentation](#présentation)
2. [Architecture](#architecture)
3. [Installation Backend](#installation-backend)
4. [Installation Extension](#installation-extension)
5. [Configuration IA](#configuration-ia)
6. [Utilisation de l'API](#utilisation-de-lapi)
7. [Règles heuristiques](#règles-heuristiques)
8. [Sécurité & éthique](#sécurité--éthique)
9. [Développement](#développement)

---

## Présentation

PhishGuard AI combine **15 règles heuristiques** et une **analyse IA optionnelle** pour évaluer en temps réel le risque de phishing d'une page web. Le résultat est affiché dans un popup Chrome élégant avec :

- Un **score de 0 à 100**
- Un **niveau de risque** : `LOW` / `MEDIUM` / `HIGH`
- Des **explications en français** adaptées aux non-techniciens
- Un **badge coloré** sur l'icône de l'extension
- Un **historique local** des 50 dernières analyses

---

## Architecture

```
phishguard/
├── backend/                  # Serveur FastAPI (Python)
│   ├── main.py               # Application FastAPI + routes
│   ├── analyzer.py           # Moteur d'analyse heuristique (15 règles)
│   ├── ai_analyzer.py        # Module IA (OpenAI / Ollama / désactivé)
│   ├── models.py             # Modèles Pydantic
│   └── requirements.txt      # Dépendances Python
│
└── extension/                # Extension Chrome (Manifest V3)
    ├── manifest.json          # Déclaration MV3
    ├── background.js          # Service Worker (badge, cache, auto-analyse)
    ├── content.js             # Script injecté dans les pages
    ├── popup.html             # Interface utilisateur
    ├── popup.css              # Styles dark theme
    ├── popup.js               # Logique du popup
    └── icons/                 # Icônes 16/32/48/128px
```

**Flux de données :**
```
Page web → content.js → background.js → POST /analyze → analyzer.py + ai_analyzer.py
                                    ↑                              ↓
                              popup.js ←──────── JSON (score, risk, reasons)
```

---

## Installation Backend

### Prérequis

- Python 3.11+
- pip

### Étapes

```bash
# 1. Cloner / télécharger le projet
cd phishguard/backend

# 2. Créer un environnement virtuel (recommandé)
python -m venv venv
source venv/bin/activate          # macOS/Linux
# venv\Scripts\activate           # Windows

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. (Optionnel) Configurer les variables d'environnement
cp .env.example .env
# Éditer .env selon votre configuration

# 5. Démarrer le serveur
uvicorn main:app --reload --port 8000
```

Le serveur démarre sur `http://localhost:8000`.
Documentation interactive : `http://localhost:8000/docs`

### Variables d'environnement (`.env`)

```env
# Mode IA : openai | ollama | disabled
AI_MODE=disabled

# OpenAI (si AI_MODE=openai)
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini

# Ollama (si AI_MODE=ollama)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
```

---

## Installation Extension

### Mode développeur (recommandé)

1. Ouvrir Chrome et aller sur `chrome://extensions/`
2. Activer le **Mode développeur** (interrupteur en haut à droite)
3. Cliquer sur **"Charger l'extension non empaquetée"**
4. Sélectionner le dossier `phishguard/extension/`
5. L'extension apparaît dans la barre d'outils Chrome ✅

### Vérification

- Naviguer vers n'importe quel site web
- Cliquer sur l'icône PhishGuard AI dans la barre d'outils
- Le score et les indicateurs s'affichent en quelques secondes

> ⚠️ **Important** : Le backend Python doit être démarré pour que l'extension fonctionne.

---

## Configuration IA

### Mode OpenAI

```env
AI_MODE=openai
OPENAI_API_KEY=sk-votre-cle-api
OPENAI_MODEL=gpt-4o-mini    # Recommandé pour coût/qualité
```

### Mode Ollama (local, gratuit)

```bash
# Installer Ollama : https://ollama.ai
ollama pull llama3
ollama serve
```

```env
AI_MODE=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
```

### Mode désactivé (défaut)

```env
AI_MODE=disabled
```

L'API fonctionne normalement, le champ `ai_summary` est `null`.

---

## Utilisation de l'API

### Endpoint principal : `POST /analyze`

**Requête :**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://secure-login.paypa1.com/verify?token=abc123&session=xyz",
    "title": "PayPal - Verify Your Account",
    "html_content": "<form action=\"/steal\"><input type=\"password\" name=\"pwd\"><iframe width=\"1\" height=\"1\" src=\"http://evil.com\"></iframe></form>"
  }'
```

**Réponse :**
```json
{
  "url": "https://secure-login.paypa1.com/verify?token=abc123&session=xyz",
  "score": 87,
  "risk": "HIGH",
  "reasons": [
    "Mots-clés suspects détectés : secure, login, verify. Ces termes sont fréquemment utilisés dans les pages de phishing.",
    "1 champ(s) de mot de passe détecté(s) dans le formulaire. Risque élevé de vol de credentials.",
    "1 iframe(s) cachée(s) détectée(s). Technique utilisée pour le clickjacking ou le vol de données.",
    "La page prétend appartenir à 'paypal' mais ce nom est absent du domaine réel. Usurpation d'identité probable.",
    "Possible substitution de caractères similaires dans le domaine ('1' → 'l'). Technique de typosquatting."
  ],
  "heuristics": [
    {
      "rule": "PHISHING_KEYWORDS",
      "score_contribution": 15,
      "description": "Mots-clés suspects détectés : secure, login, verify."
    }
  ],
  "ai_summary": null,
  "analyzed_at": "2024-01-15T14:32:10.123456"
}
```

### Autres endpoints

| Méthode | Route       | Description                          |
|---------|-------------|--------------------------------------|
| GET     | `/health`   | État du service et mode IA actif     |
| GET     | `/history`  | Historique des analyses (`?limit=20`) |
| GET     | `/stats`    | Statistiques globales               |
| DELETE  | `/history`  | Efface l'historique en mémoire      |
| GET     | `/docs`     | Documentation Swagger interactive   |

---

## Règles heuristiques

| Règle                  | Poids | Description                                      |
|------------------------|-------|--------------------------------------------------|
| `URL_LENGTH`           | 10    | URL > 75 caractères                              |
| `SUBDOMAIN_COUNT`      | 15    | Plus de 2 sous-domaines                         |
| `IP_IN_URL`            | 25    | Adresse IP au lieu d'un nom de domaine          |
| `UNICODE_SUSPICIOUS`   | 20    | Caractères non-ASCII dans le domaine (IDN)      |
| `HOMOGLYPH`            | 20    | Substitution visuelle (0→o, 1→l, rn→m...)       |
| `PHISHING_KEYWORDS`    | 15    | login, verify, secure, update, banking...       |
| `HTTPS_MISSING`        | 10    | Absence de HTTPS                                |
| `AT_SYMBOL_IN_URL`     | 20    | Symbole `@` dans l'URL                          |
| `DOUBLE_SLASH_REDIRECT`| 15    | Double slash `//` dans le chemin                |
| `PASSWORD_FORM`        | 20    | Champ `<input type="password">` détecté         |
| `HIDDEN_IFRAME`        | 20    | Iframe cachée ou de taille 0                    |
| `EXTERNAL_LINKS_HIGH`  | 10    | Plus de 20 liens externes                       |
| `SUSPICIOUS_PORT`      | 15    | Port non standard (pas 80/443/8080/8443)        |
| `DATA_URI`             | 20    | URL de type `data:`                             |
| `TITLE_MISMATCH`       | 10    | Marque connue dans le titre, absente du domaine |

**Score final** : normalisé via une courbe logistique (score brut 30 → ~50, 60 → ~85)

**Niveaux de risque** :
- `LOW` : score < 35
- `MEDIUM` : score 35–64
- `HIGH` : score ≥ 65

---

## Sécurité & éthique

PhishGuard AI respecte les principes suivants :

- ✅ **Lecture seule** : Ne modifie jamais le contenu des pages
- ✅ **Pas de blocage automatique** : Fournit uniquement un score et des recommandations
- ✅ **Pas de collecte de données personnelles** : Le HTML est analysé localement et tronqué
- ✅ **Pas de mots de passe** : Le content script ne lit jamais la valeur des champs password
- ✅ **Transparence** : Chaque indicateur est expliqué en langage clair
- ✅ **Local by default** : Toutes les analyses peuvent fonctionner 100% en local (mode `disabled`)

---

## Développement

### Tests rapides

```bash
# Tester avec une URL suspecte
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"http://192.168.1.1/login?verify=true&secure=1","title":"Bank Login"}' \
  | python3 -m json.tool

# Tester avec une URL normale
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.google.com"}' \
  | python3 -m json.tool

# Voir les stats
curl -s http://localhost:8000/stats | python3 -m json.tool
```

### Ajouter une règle heuristique

Dans `analyzer.py`, ajouter dans `_build_rules()` :

```python
("MA_REGLE", self._rule_ma_regle, 15),
```

Puis implémenter la méthode :

```python
def _rule_ma_regle(self, url, parsed, title, soup):
    """Description de la règle."""
    if condition:
        return True, "Explication humaine de ce qui a été détecté."
    return False, ""
```

---

## Licence

MIT — Utilisation libre pour projets éducatifs et de recherche en cybersécurité.
