#!/usr/bin/env python3
"""Lit (sans rien modifier) toutes les propriétés ACP d'une Time Capsule.

    .re-tools/venv/bin/python outils/acp-lire.py [--hote IP] [--sortie sauvegardes/acp-AAAAMMJJ-HHMM.json]
    .re-tools/venv/bin/python outils/acp-lire.py --comparer avant.json apres.json
    .re-tools/venv/bin/python outils/acp-lire.py --redecoder sauvegardes/acp-….json

Mot de passe : voir outils/motdepasse.py (variable, trousseau, fenêtre macOS).
Il n'est jamais écrit dans un fichier. Seule la commande ACP « lire une propriété » (0x14)
est envoyée. La liste des 533 propriétés vient de docs/proprietes-acp.tsv
(table relevée dans ACPd 7.9.1).

Attention : ce protocole ACP ancien protège mal le mot de passe sur le réseau ;
à n'utiliser que sur le réseau local.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import plistlib
import struct
import sys

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "upstream" / "src"))

from timecapsulesmb.integrations.acp import ACPError, get_properties  # noqa: E402

import cfb  # noqa: E402  (outils/, à côté de ce script)
import config  # noqa: E402
import motdepasse  # noqa: E402

LOT = 20  # propriétés par requête


def charger_table() -> list[tuple[str, int]]:
    lignes = (RACINE / "docs" / "proprietes-acp.tsv").read_text().splitlines()[1:]
    return [(c[0], int(c[1])) for c in (l.split("\t") for l in lignes)]


def decoder(type_acpd: int, brut: bytes) -> object:
    """Valeur lisible selon le type ACPd ; le brut reste toujours conservé."""
    try:
        if type_acpd == 5 and len(brut) == 4:
            return struct.unpack(">I", brut)[0]
        if type_acpd in (2, 9, 11):
            return brut.rstrip(b"\0").decode("utf-8")
        if type_acpd == 8 and len(brut) == 6:
            return ":".join(f"{b:02X}" for b in brut)
        if type_acpd == 13 and brut[:4] == cfb.ENTETE:
            return _jsonable(cfb.lire(brut))
        if type_acpd == 13 and brut[:6] == b"bplist":
            return _jsonable(plistlib.loads(brut))
    except Exception:
        pass
    return None


def _jsonable(o: object) -> object:
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, bytes):
        return {"hex": o.hex()}
    if isinstance(o, (dt.datetime, dt.date)):
        return o.isoformat()
    return o


def lire(hote: str, mot_de_passe: str) -> dict[str, object]:
    table = charger_table()
    resultat: dict[str, object] = {}
    for i in range(0, len(table), LOT):
        lot = table[i : i + LOT]
        noms = tuple(n for n, _ in lot)
        try:
            valeurs = get_properties(hote, mot_de_passe, noms)
        except ACPError as exc:
            if "password" in str(exc).lower() or "auth" in type(exc).__name__.lower():
                raise
            # Une requête groupée refusée : on retente une par une.
            valeurs = {}
            for n in noms:
                try:
                    valeurs.update(get_properties(hote, mot_de_passe, (n,)))
                except ACPError as exc1:
                    valeurs[n] = exc1
        for nom, type_acpd in lot:
            v = valeurs.get(nom)
            if v is None:
                resultat[nom] = {"absent": True}
            elif isinstance(v, Exception):
                resultat[nom] = {"erreur": str(v)}
            else:
                entree: dict[str, object] = {"type": type_acpd, "hex": v.hex()}
                lisible = decoder(type_acpd, v)
                if lisible is not None:
                    entree["valeur"] = lisible
                resultat[nom] = entree
        print(f"\r{min(i + LOT, len(table))}/{len(table)} propriétés lues", end="", file=sys.stderr)
    print(file=sys.stderr)
    return resultat


def _ecarts(chemin: str, a: object, b: object) -> list[str]:
    """Différences feuille par feuille, pour voir quel réglage a bougé dans WiFi."""
    if isinstance(a, dict) and isinstance(b, dict):
        return [e for k in sorted(set(a) | set(b), key=str)
                for e in _ecarts(f"{chemin}.{k}", a.get(k, "∅"), b.get(k, "∅"))]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [e for i, (x, y) in enumerate(zip(a, b)) for e in _ecarts(f"{chemin}[{i}]", x, y)]
    return [] if a == b else [f"{chemin}: {a!r} -> {b!r}"]


def comparer(avant: Path, apres: Path) -> int:
    a = json.loads(avant.read_text())["proprietes"]
    b = json.loads(apres.read_text())["proprietes"]
    diff = 0
    for nom in sorted(set(a) | set(b)):
        va, vb = a.get(nom, {}), b.get(nom, {})
        if va == vb:
            continue
        diff += 1
        if "valeur" in va and "valeur" in vb:
            for ligne in _ecarts(nom, va["valeur"], vb["valeur"]):
                print(ligne)
        else:
            print(f"{nom}: {va.get('hex', va)!r} -> {vb.get('hex', vb)!r}")
    print(f"{diff} propriété(s) différente(s)")
    return 0


def redecoder(fichier: Path) -> int:
    """Refait le décodage lisible d'un relevé à partir des octets bruts conservés."""
    doc = json.loads(fichier.read_text())
    for v in doc["proprietes"].values():
        if "hex" in v:
            lisible = decoder(v["type"], bytes.fromhex(v["hex"]))
            if lisible is not None:
                v["valeur"] = lisible
    fichier.write_text(json.dumps(doc, indent=1, ensure_ascii=False))
    print(f"{fichier} redécodé")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--hote", help="défaut : TC_HOTE (config.local)")
    p.add_argument("--sortie", type=Path)
    p.add_argument("--comparer", nargs=2, type=Path, metavar=("AVANT", "APRES"))
    p.add_argument("--redecoder", type=Path, metavar="RELEVE")
    a = p.parse_args()
    a.hote = a.hote or config.hote()
    if a.comparer:
        return comparer(*a.comparer)
    if a.redecoder:
        return redecoder(a.redecoder)

    mot_de_passe = motdepasse.obtenir()
    props = lire(a.hote, mot_de_passe)
    sortie = a.sortie or RACINE / "sauvegardes" / f"acp-{dt.datetime.now():%Y%m%d-%H%M}.json"
    sortie.parent.mkdir(parents=True, exist_ok=True)
    # syPW contient le mot de passe : jamais enregistré.
    props.pop("syPW", None)
    sortie.write_text(json.dumps({"hote": a.hote, "date": dt.datetime.now().isoformat(),
                                  "proprietes": props}, indent=1, ensure_ascii=False))
    lues = sum(1 for v in props.values() if "hex" in v)
    print(f"{lues} propriétés lues, enregistrées dans {sortie}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
