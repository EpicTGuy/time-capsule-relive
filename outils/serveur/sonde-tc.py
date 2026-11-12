#!/usr/bin/env python3
"""Sonde de la Time Capsule, lancée par serveur-maison toutes les 10 minutes.

    sonde-tc.py            contrôle + alertes ntfy si un état change
    sonde-tc.py --etat     affiche l'état sans alerter

Lecture seule : uniquement la commande ACP « lire une propriété » (comme
l'Utilitaire AirPort) et une connexion TCP au port SMB. Python standard seul.

Configuration : /root/.config/sonde-tc.env (droits 600)
    TC_HOTE=192.168.1.20
    TC_PASSWORD=…
    NTFY_URL=https://ntfy.example/sujet
    NTFY_TOKEN=tk_…
État et historique : /var/lib/sonde-tc/etat.json
"""
from __future__ import annotations

import json
from pathlib import Path
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cfb  # noqa: E402  (copié à côté : outils/cfb.py)

CONF = Path("/root/.config/sonde-tc.env")
ETAT = Path("/var/lib/sonde-tc/etat.json")
JOURNAL_SAUVEGARDE = Path("/var/log/sauvegarde-immich.log")

SEUIL_DISQUE_LIBRE = 0.10      # alerte sous 10 % libres
SEUIL_TEMPERATURE = 70         # °C, capteurs T_internal / T_external*
DELAI_SAUVEGARDE = 36 * 3600   # alerte si pas de sauvegarde Immich réussie depuis 36 h
RAPPEL = 24 * 3600             # rappel d'une alerte toujours active


# --- ACP minimal (lecture), d'après TimeCapsuleSMB integrations/acp.py (GPL-3.0) ---
_CLE = bytes.fromhex("5b6faf5d9d5b0e1351f2da1de7e8d673")
_ENTETE = struct.Struct("!4s8i12x32s48x")


def _adler(d: bytes) -> int:
    v = zlib.adler32(d) & 0xFFFFFFFF
    return v - (1 << 32) if v >= 1 << 31 else v


def _entete(mdp: str, corps: bytes) -> bytes:
    pw = mdp.encode()[:32].ljust(32, b"\0")
    cle = bytes(((i + 0x55) & 0xFF) ^ _CLE[i % 16] ^ pw[i] for i in range(32))
    args = (b"acpp", 0x00030001, 0, _adler(corps), len(corps), 4, 0, 0x14, 0, cle)
    provisoire = _ENTETE.pack(*args)
    return _ENTETE.pack(*args[:2], _adler(provisoire), *args[3:])


def _lire_exact(s: socket.socket, n: int) -> bytes:
    b = b""
    while len(b) < n:
        m = s.recv(n - len(b))
        if not m:
            raise ConnectionError("connexion ACP fermée")
        b += m
    return b


def acp_lire(hote: str, mdp: str, noms: tuple[str, ...]) -> dict[str, bytes]:
    corps = b"".join(struct.pack("!4s2I", n.encode(), 0, 4) + b"\0" * 4 for n in noms)
    with socket.create_connection((hote, 5009), timeout=20) as s:
        s.sendall(_entete(mdp, corps) + corps)
        h = _ENTETE.unpack(_lire_exact(s, _ENTETE.size))
        if h[8] != 0:
            raise PermissionError(f"ACP refusé (code {h[8]}) : mot de passe ?")
        taille = h[4]
        donnees = _lire_exact(s, taille) if taille > 0 else None
        res: dict[str, bytes] = {}
        pos = 0
        while True:
            if donnees is None:
                t = _lire_exact(s, 12)
            else:
                if pos >= len(donnees):
                    break
                t = donnees[pos:pos + 12]
                pos += 12
            nom, drapeaux, n = struct.unpack("!4s2I", t)
            if nom == b"\0\0\0\0":
                break
            if donnees is None:
                v = _lire_exact(s, n)
            else:
                v, pos = donnees[pos:pos + n], pos + n
            if not drapeaux & 1:
                res[nom.decode()] = v
            if donnees is None and len(res) == len(noms):
                break
        return res


# --- contrôles ---
def charger_conf() -> dict[str, str]:
    conf = {}
    for ligne in CONF.read_text().splitlines():
        if "=" in ligne and not ligne.lstrip().startswith("#"):
            k, v = ligne.split("=", 1)
            conf[k.strip()] = v.strip().strip('"')
    return conf


def port_ouvert(hote: str, port: int) -> bool:
    try:
        with socket.create_connection((hote, port), timeout=5):
            return True
    except OSError:
        return False


def derniere_sauvegarde() -> float | None:
    if not JOURNAL_SAUVEGARDE.exists():
        return None
    for ligne in reversed(JOURNAL_SAUVEGARDE.read_text(errors="replace").splitlines()):
        if ligne.endswith("sauvegarde : fin"):
            return time.mktime(time.strptime(ligne[:19], "%Y-%m-%d %H:%M:%S"))
    return None


SMART_CRITIQUES = {5: "secteurs réalloués", 187: "erreurs non corrigées", 197: "secteurs en attente",
                   198: "secteurs illisibles hors ligne"}
SEUIL_TEMP_DISQUE = 58  # °C (attribut SMART 194)


def lire_smart(conf: dict[str, str]) -> tuple[dict[int, tuple[int, int, int]], float | None]:
    """Relevé SMART écrit toutes les 30 min par la Time Capsule (atactl) dans
    .seconde-vie/smart.txt, lu par SMB. Renvoie {id: (valeur, seuil, brut)}, âge en s."""
    r = subprocess.run(["smbclient", "-m", "SMB3", "-U", "admin", f"//{conf['TC_HOTE']}/Data",
                        "-c", r"allinfo .seconde-vie\smart.txt; get .seconde-vie\smart.txt -"],
                       env={**os.environ, "PASSWD": conf["TC_PASSWORD"]},
                       capture_output=True, text=True, timeout=60)
    attrs, age = {}, None
    for ligne in r.stdout.splitlines():
        if ligne.startswith("write_time:"):
            try:
                t = time.strptime(ligne.split(":", 1)[1].strip()[:24], "%a %b %d %H:%M:%S %Y")
                age = time.time() - time.mktime(t)
            except ValueError:
                pass
        champs = ligne.split()
        if len(champs) >= 3 and champs[0].isdigit() and champs[1].isdigit() and champs[2].isdigit():
            brut = champs[-1] if champs[-1].isdigit() else "0"
            # « 55 Lifetime min/max … » : la valeur brute de température précède « Lifetime »
            if "Lifetime" in champs:
                brut = champs[champs.index("Lifetime") - 1]
            attrs[int(champs[0])] = (int(champs[1]), int(champs[2]), int(brut))
    return attrs, age


def controler(conf: dict[str, str]) -> tuple[dict[str, str], dict]:
    """Renvoie (alertes actives {clé: message}, mesures)."""
    hote, alertes, mesures = conf["TC_HOTE"], {}, {}
    try:
        p = acp_lire(hote, conf["TC_PASSWORD"], ("MaSt", "sySI", "sySt", "syUT"))
    except Exception as exc:
        alertes["injoignable"] = f"Time Capsule injoignable par ACP : {exc}"
        return alertes, mesures

    mesures["demarree_depuis_h"] = round(struct.unpack(">I", p["syUT"])[0] / 3600, 1)
    for prob in cfb.lire(p["sySt"]).get("problems", []):
        code = prob.get("code", "?")
        alertes[f"probleme-{code}"] = f"La Time Capsule signale le problème « {code} »"

    for disque in cfb.lire(p["MaSt"]):
        for part in disque.get("partitions", []):
            taille, libre = part.get("size", 0), part.get("sizeFree", 0)
            if taille:
                mesures[f"libre_{part.get('name')}_go"] = round(libre / 1024, 1)
                if libre / taille < SEUIL_DISQUE_LIBRE:
                    alertes[f"disque-{part.get('name')}"] = (
                        f"Disque {part.get('name')} : seulement {libre / 1024:.0f} Go libres "
                        f"({100 * libre / taille:.0f} %)")
    if not cfb.lire(p["MaSt"]):
        alertes["disque-absent"] = "Aucun disque vu par la Time Capsule"

    for capteur in cfb.lire(p["sySI"]):
        nom, val = capteur.get("name", ""), capteur.get("value", 0)
        mesures[nom] = val
        if nom.startswith("T_") and nom != "T_hdd" and val > SEUIL_TEMPERATURE:
            alertes[f"chaud-{nom}"] = f"Température {nom} : {val} °C"
    if mesures.get("Fan_rpm") == 0:
        alertes["ventilateur"] = "Ventilateur à l'arrêt"

    if not port_ouvert(hote, 445):
        alertes["smb"] = "Partage SMB (port 445) injoignable : Samba arrêté ?"
    else:
        try:
            smart, age = lire_smart(conf)
        except Exception as exc:
            smart, age = {}, None
            alertes["smart-lecture"] = f"Relevé SMART illisible : {exc}"
        if smart:
            for ident, nom in SMART_CRITIQUES.items():
                if ident in smart and smart[ident][2] > 0:
                    alertes[f"smart-{ident}"] = f"Disque : {smart[ident][2]} {nom} (SMART {ident})"
            if 194 in smart:
                mesures["T_disque_smart"] = smart[194][2]
                if smart[194][2] >= SEUIL_TEMP_DISQUE:
                    alertes["smart-temperature"] = f"Disque à {smart[194][2]} °C (SMART 194)"
            if 9 in smart:
                mesures["disque_heures"] = smart[9][2]
            for ident, (valeur, seuil, _) in smart.items():
                if seuil and valeur <= seuil and ident not in (190,):
                    alertes[f"smart-seuil-{ident}"] = f"Attribut SMART {ident} au seuil ({valeur} ≤ {seuil})"
            if age is not None and age > 3 * 3600:
                alertes["smart-ancien"] = f"Relevé SMART vieux de {age / 3600:.0f} h"

    t = derniere_sauvegarde()
    if t is not None:
        mesures["derniere_sauvegarde_immich_h"] = round((time.time() - t) / 3600, 1)
        if time.time() - t > DELAI_SAUVEGARDE:
            alertes["sauvegarde-immich"] = (
                f"Pas de sauvegarde Immich réussie depuis {(time.time() - t) / 3600:.0f} h")
    return alertes, mesures


def notifier(conf: dict[str, str], titre: str, message: str, priorite: str, tags: str) -> None:
    if not conf.get("NTFY_URL"):
        return
    req = urllib.request.Request(conf["NTFY_URL"], message.encode(), {
        "Title": titre.encode("utf-8").decode("latin-1"), "Priority": priorite, "Tags": tags,
        **({"Authorization": f"Bearer {conf['NTFY_TOKEN']}"} if conf.get("NTFY_TOKEN") else {})})
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as exc:
        print("ntfy :", exc, file=sys.stderr)


def main() -> int:
    conf = charger_conf()
    alertes, mesures = controler(conf)
    if "--etat" in sys.argv:
        print(json.dumps({"alertes": alertes, "mesures": mesures}, indent=1, ensure_ascii=False))
        return 0

    ETAT.parent.mkdir(parents=True, exist_ok=True)
    avant = json.loads(ETAT.read_text()) if ETAT.exists() else {"alertes": {}}
    maintenant = time.time()
    actives = {}
    for cle, msg in alertes.items():
        deja = avant["alertes"].get(cle)
        if deja is None or maintenant - deja["depuis_rappel"] > RAPPEL:
            notifier(conf, "Time Capsule : alerte", msg, "high", "warning,floppy_disk")
            actives[cle] = {"message": msg, "depuis_rappel": maintenant}
        else:
            actives[cle] = deja
    for cle, deja in avant["alertes"].items():
        if cle not in alertes:
            notifier(conf, "Time Capsule : rétabli", f"Résolu : {deja['message']}", "default",
                     "white_check_mark,floppy_disk")
    ETAT.write_text(json.dumps({"alertes": actives, "mesures": mesures, "controle": maintenant},
                               indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
