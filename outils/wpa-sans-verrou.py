#!/usr/bin/env python3
"""Prépare un wpa_supplicant sans le verrou « routeur Apple seulement » du mode DWDS.

    .re-tools/venv/bin/python outils/wpa-sans-verrou.py

En mode répéteur (DWDS), ACPd écrit `dwds_role=3` dans la configuration du
supplicant ; la fonction qui compare les réseaux candidats (firmware 7.9.1,
adresse 0x1f87d8) écarte alors tout réseau qui n'annonce pas l'élément Apple
DWDS (`dd 0b 00 17 f2 01 …`) : aucune association n'est tentée vers un routeur
non Apple. On neutralise ce seul branchement (4 octets).

Rien d'Apple n'est distribué : le programme est lu sur VOTRE Time Capsule
(/sbin/wpa_supplicant), vérifié par son empreinte SHA-256 (firmware 7.9.1),
corrigé sur le Mac, puis renvoyé sur son disque (.seconde-vie/bin/). Le
firmware n'est pas modifié ; un redémarrage remet tout comme avant.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys

RACINE = Path(__file__).resolve().parent.parent
SSH = [str(RACINE / "outils" / "tc-ssh.sh")]
DOSSIER = "/Volumes/dk2/.seconde-vie/bin"

SHA256_791 = "7a1e5fae541f8fd112d98f261b18eb3ac3ac1c8be02e3223660d5b1b7cc2e05b"
# vaddr 0x1f8808 (segment chargé à 0x8000, offset fichier 0) :
#   beq 0x1f8a48  (« dwds_role == 3 et réseau sans DWDS → refus »)  →  nop (mov r0, r0)
CORRECTIFS = [(0x1F8808 - 0x8000, bytes.fromhex("8e00000a"), bytes.fromhex("0000a0e1"))]


def main() -> int:
    orig = subprocess.run(SSH + ["/bin/cat /sbin/wpa_supplicant"], capture_output=True, check=True).stdout
    empreinte = hashlib.sha256(orig).hexdigest()
    if empreinte != SHA256_791:
        print(f"wpa_supplicant inattendu (SHA-256 {empreinte}) : firmware autre que 7.9.1 ? Rien n'est fait.")
        return 1
    data = bytearray(orig)
    for pos, avant, apres in CORRECTIFS:
        if data[pos:pos + len(avant)] != avant:
            print(f"octets inattendus à 0x{pos:x} : rien n'est fait.")
            return 1
        data[pos:pos + len(apres)] = apres
    subprocess.run(SSH + [f"/bin/cat > {DOSSIER}/wpa_supplicant.nouveau && /bin/chmod 755 {DOSSIER}/wpa_supplicant.nouveau"
                          f" && /bin/mv {DOSSIER}/wpa_supplicant.nouveau {DOSSIER}/wpa_supplicant-dwds"],
                   input=bytes(data), check=True)
    print(f"Écrit : {DOSSIER}/wpa_supplicant-dwds (SHA-256 {hashlib.sha256(data).hexdigest()[:16]}…)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
