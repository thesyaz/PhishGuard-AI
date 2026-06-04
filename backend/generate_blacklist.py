#!/usr/bin/env python3
"""
PhishGuard AI - Générateur de blacklist

Convertit le dataset malicious_phish.csv en blacklist.json optimisée
pour un chargement rapide en mémoire.

Usage :
  python generate_blacklist.py                            # utilise malicious_phish.csv par défaut
  python generate_blacklist.py --input mon_dataset.csv   # fichier personnalisé
  python generate_blacklist.py --types phishing malware  # types à inclure
  python generate_blacklist.py --stats                   # affiche seulement les stats

Format CSV attendu :
  url,type
  http://evil-site.com,phishing
  malware-host.net,malware
  ...
"""

import argparse
import json
import os
import sys
from urllib.parse import urlparse

try:
    import pandas as pd
except ImportError:
    print("❌ pandas requis : pip install pandas")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_INPUT  = os.path.join(os.path.dirname(__file__), "malicious_phish.csv")
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "blacklist.json")
DEFAULT_CSV    = os.path.join(os.path.dirname(__file__), "blacklist.csv")

# Domaines légitimes à exclure malgré leur présence dans le dataset
FALSE_POSITIVE_DOMAINS = {
    "google.com", "docs.google.com", "drive.google.com", "maps.google.com",
    "facebook.com", "instagram.com", "twitter.com", "youtube.com",
    "microsoft.com", "live.com", "outlook.com", "hotmail.com",
    "apple.com", "icloud.com", "yahoo.com", "amazon.com",
    "github.com", "pastehtml.com", "angelfire.com", "pastebin.com",
    "blogspot.com", "wordpress.com",
}


# ---------------------------------------------------------------------------
# Extraction de domaine
# ---------------------------------------------------------------------------

def extract_domain(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        host = urlparse(url).hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host.lower()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Script principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Génère la blacklist PhishGuard AI depuis un dataset CSV"
    )
    parser.add_argument(
        "--input", default=DEFAULT_INPUT,
        help=f"Chemin vers le fichier CSV (défaut: {DEFAULT_INPUT})"
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Chemin de sortie JSON (défaut: {DEFAULT_OUTPUT})"
    )
    parser.add_argument(
        "--types", nargs="+", default=["phishing", "malware"],
        help="Types de menaces à inclure (défaut: phishing malware)"
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Affiche uniquement les statistiques du CSV sans générer la blacklist"
    )
    args = parser.parse_args()

    # Vérification du fichier d'entrée
    if not os.path.exists(args.input):
        print(f"❌ Fichier introuvable : {args.input}")
        print("   Téléchargez le dataset sur : https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset")
        sys.exit(1)

    print(f"📂 Lecture de {args.input}...")
    df = pd.read_csv(args.input)

    # Vérification des colonnes
    required_cols = {"url", "type"}
    if not required_cols.issubset(df.columns):
        print(f"❌ Le CSV doit contenir les colonnes : {required_cols}")
        print(f"   Colonnes trouvées : {set(df.columns)}")
        sys.exit(1)

    print(f"\n📊 Distribution dans le dataset ({len(df):,} lignes) :")
    print(df["type"].value_counts().to_string())

    if args.stats:
        return

    # Filtrage par types de menaces
    print(f"\n🔍 Filtrage des types : {args.types}...")
    dangerous = df[df["type"].isin(args.types)].copy()
    print(f"   → {len(dangerous):,} entrées retenues")

    # Extraction des domaines
    print("🌐 Extraction des domaines...")
    dangerous["domain"] = dangerous["url"].apply(extract_domain)
    dangerous = dangerous[dangerous["domain"] != ""]

    # Déduplique + filtre faux positifs
    unique = dangerous[["domain", "type"]].drop_duplicates(subset="domain")
    before = len(unique)
    unique = unique[~unique["domain"].isin(FALSE_POSITIVE_DOMAINS)]
    removed = before - len(unique)
    if removed > 0:
        print(f"   → {removed} faux positifs supprimés")

    print(f"   → {len(unique):,} domaines uniques")

    # Construction du dictionnaire {domain: type}
    blacklist = dict(zip(unique["domain"], unique["type"]))

    # Sauvegarde JSON
    print(f"\n💾 Sauvegarde JSON → {args.output}")
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(blacklist, f, separators=(",", ":"))
    size_kb = os.path.getsize(args.output) / 1024
    print(f"   ✅ {len(blacklist):,} domaines · {size_kb:.0f} KB")

    # Sauvegarde CSV (référence lisible)
    csv_path = args.output.replace(".json", ".csv")
    unique.to_csv(csv_path, index=False)
    print(f"   ✅ CSV de référence → {csv_path}")

    print("\n🎉 Blacklist prête ! Redémarrez le backend pour la prendre en compte.")
    print("   Ou appelez POST /blacklist/reload pour un rechargement à chaud.")


if __name__ == "__main__":
    main()
