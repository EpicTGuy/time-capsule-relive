#!/usr/bin/env python3
"""Télécharge et déchiffre le logiciel Apple d'une Time Capsule, pour l'analyser.

    .re-tools/venv/bin/python outils/firmware-extraire.py [--produit 119] [--version 7.9.1]

Réutilise le code de TimeCapsuleSMB (upstream/src) : catalogue Apple
apsu.apple.com/version.xml, conteneurs « basebinary » imbriqués, clé du modèle.
Le résultat va dans binaires/ (exclu du dépôt) : on ne redistribue jamais le
logiciel d'Apple, seulement cet outil et nos notes.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "upstream" / "src"))

from timecapsulesmb.apple_firmware import (  # noqa: E402
    load_apple_firmware_catalog,
    read_cached_or_download_template,
)
from timecapsulesmb.basebinary import parse_nested_basebinary  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--produit", default="119", help="identifiant AirPort syAP (119 = Time Capsule 802.11ac)")
    parser.add_argument("--version", default="7.9.1")
    parser.add_argument("--sortie", type=Path, default=RACINE / "binaires" / "firmware")
    args = parser.parse_args()

    cache = args.sortie / "cache"
    entries = [
        e for e in load_apple_firmware_catalog(cache_dir=cache)
        if str(e.get("productID")) == args.produit and str(e.get("version")) == args.version
    ]
    if not entries:
        print(f"Aucune entrée {args.produit} / {args.version} dans le catalogue Apple", file=sys.stderr)
        return 1

    candidate = read_cached_or_download_template(entries[0], cache_dir=cache)
    print(f"source  : {candidate.source}")
    print(f"taille  : {len(candidate.data)} octets, sha256 {hashlib.sha256(candidate.data).hexdigest()}")

    nested = parse_nested_basebinary(candidate.data)
    for nom, conteneur in (("externe", nested.outer), ("interne", nested.inner)):
        h = conteneur.header
        print(f"{nom:8}: modèle {h.model}, version {h.version:#x}, chiffré {h.encrypted}, "
              f"clé {conteneur.key.key_id if conteneur.key else '-'}")

    sortie = args.sortie / f"{args.produit}-{args.version}.payload"
    sortie.write_bytes(nested.inner.payload)
    print(f"charge utile déchiffrée : {sortie} ({len(nested.inner.payload)} octets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
