"""Paramètres locaux des outils : variable d'environnement, sinon fichier
config.local à la racine du projet (non versionné), sinon valeur par défaut.

    # config.local
    TC_HOTE=192.168.1.20
"""
from __future__ import annotations

import os
from pathlib import Path

FICHIER = Path(__file__).resolve().parent.parent / "config.local"


def valeur(nom: str, defaut: str | None = None) -> str | None:
    if os.environ.get(nom):
        return os.environ[nom]
    if FICHIER.exists():
        for ligne in FICHIER.read_text().splitlines():
            if "=" in ligne and not ligne.lstrip().startswith("#"):
                k, v = ligne.split("=", 1)
                if k.strip() == nom:
                    return v.strip().strip('"')
    return defaut


def hote() -> str:
    h = valeur("TC_HOTE")
    if not h:
        raise SystemExit("Adresse de la Time Capsule inconnue : définir TC_HOTE "
                         "(variable d'environnement ou fichier config.local).")
    return h
