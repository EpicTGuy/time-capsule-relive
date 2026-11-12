#!/usr/bin/env python3
"""Liste ce qu'une sauvegarde contient et qui n'existe plus sur le Mac actuel.

    python3 outils/comparer-sauvegarde.py <dossier utilisateur dans la sauvegarde> \
        [--mac ~] [--exclure ~/Library ~/Sauvegardes-TimeCapsule] [--rapport sauvegardes/comparaison]

Un fichier de la sauvegarde est « retrouvé » si un fichier de même nom et de
même taille existe n'importe où sous --mac (il a pu être rangé ailleurs).
Lecture seule des deux côtés. Sorties :
  <rapport>/resume.txt          par dossier : fichiers, volume, manquants
  <rapport>/manquants.tsv       chemin, taille, date de modification
  <rapport>/manquants-par-dossier.tsv   volume manquant agrégé par sous-dossier
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import datetime as dt
import os
from pathlib import Path
import sys

IGNORES = {".DS_Store", ".localized", "Icon\r", ".com.apple.timemachine.supported"}


def parcourir(racine: Path, exclure: set[Path]):
    pile = [racine]
    while pile:
        d = pile.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            p = Path(e.path)
                            if p not in exclure:
                                pile.append(p)
                        elif e.is_file(follow_symlinks=False):
                            if e.name in IGNORES or e.name.startswith("._"):
                                continue
                            yield e
                    except OSError:
                        continue
        except OSError:
            continue


def go(o: int) -> str:
    return f"{o / 1e9:.2f} Go" if o >= 1e8 else f"{o / 1e6:.1f} Mo"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("sauvegarde", type=Path)
    p.add_argument("--mac", type=Path, default=Path.home())
    p.add_argument("--exclure", type=Path, nargs="*",
                   default=[Path.home() / "Library", Path.home() / "Sauvegardes-TimeCapsule", Path.home() / ".Trash"])
    p.add_argument("--rapport", type=Path, default=Path("sauvegardes/comparaison"))
    p.add_argument("--ignorer-dossiers", nargs="*", default=["Library"],
                   help="sous-dossiers de la sauvegarde à ne pas comparer")
    a = p.parse_args()

    print(f"index du Mac actuel ({a.mac})…", file=sys.stderr, flush=True)
    index: set[tuple[str, int]] = set()
    n = 0
    for e in parcourir(a.mac, set(a.exclure)):
        try:
            index.add((e.name, e.stat(follow_symlinks=False).st_size))
        except OSError:
            continue
        n += 1
        if n % 200000 == 0:
            print(f"  {n} fichiers indexés", file=sys.stderr, flush=True)
    print(f"  {n} fichiers indexés au total", file=sys.stderr, flush=True)

    a.rapport.mkdir(parents=True, exist_ok=True)
    par_haut: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])  # fichiers, octets, manquants, octets manquants
    par_dossier: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    with open(a.rapport / "manquants.tsv", "w") as out:
        out.write("chemin\ttaille\tmodifie\n")
        for haut in sorted(os.listdir(a.sauvegarde)):
            if haut in a.ignorer_dossiers:
                continue
            racine = a.sauvegarde / haut
            fichiers = [racine] if racine.is_file() else None
            entrees = (os.scandir(racine.parent) if fichiers else parcourir(racine, set()))
            for e in entrees:
                if fichiers and e.name != haut:
                    continue
                st = e.stat(follow_symlinks=False)
                stats = par_haut[haut]
                stats[0] += 1
                stats[1] += st.st_size
                if (e.name, st.st_size) in index:
                    continue
                stats[2] += 1
                stats[3] += st.st_size
                rel = os.path.relpath(e.path, a.sauvegarde)
                out.write(f"{rel}\t{st.st_size}\t{dt.datetime.fromtimestamp(st.st_mtime):%Y-%m-%d}\n")
                parties = rel.split(os.sep)[:-1]
                for k in range(1, min(len(parties), 3) + 1):
                    cle = "/".join(parties[:k])
                    par_dossier[cle][0] += 1
                    par_dossier[cle][1] += st.st_size

    lignes = [f"{'dossier':32} {'fichiers':>9} {'volume':>11} {'manquants':>10} {'vol. manquant':>13}"]
    for haut, (nf, vo, nm, vm) in sorted(par_haut.items(), key=lambda kv: -kv[1][3]):
        lignes.append(f"{haut[:32]:32} {nf:>9} {go(vo):>11} {nm:>10} {go(vm):>13}")
    tot = [sum(v[i] for v in par_haut.values()) for i in range(4)]
    lignes.append(f"{'TOTAL':32} {tot[0]:>9} {go(tot[1]):>11} {tot[2]:>10} {go(tot[3]):>13}")
    (a.rapport / "resume.txt").write_text("\n".join(lignes) + "\n")
    with open(a.rapport / "manquants-par-dossier.tsv", "w") as out:
        out.write("dossier\tfichiers\toctets\n")
        for cle, (nf, vo) in sorted(par_dossier.items(), key=lambda kv: -kv[1][1]):
            out.write(f"{cle}\t{nf}\t{vo}\n")
    print("\n".join(lignes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
