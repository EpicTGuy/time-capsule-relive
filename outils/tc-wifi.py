#!/usr/bin/env python3
"""Règle le Wi-Fi d'une Time Capsule sans l'Utilitaire AirPort (propriété ACP « WiFi »).

    tc-wifi.py voir                                   # résumé lisible, secrets masqués
    tc-wifi.py client --radio 0 --ssid NOM [--securite 5] [--sans-dwds]
                                                      # radio en client Wi-Fi (répéteur)
    tc-wifi.py point-acces --radio 0                  # radio en point d'accès
    tc-wifi.py restaurer sauvegardes/wifi-….cfb       # remet une configuration à l'identique

Chaque écriture :
  1. relit la configuration actuelle et la sauvegarde telle quelle
     (sauvegardes/wifi-AAAAMMJJ-HHMMSS.cfb, octets exacts) ;
  2. affiche les changements et demande confirmation (sauf --oui) ;
  3. écrit la propriété « WiFi », puis redémarre l'appareil (acRB) sauf --sans-redemarrer.
Le mot de passe Wi-Fi du réseau à rejoindre est demandé par fenêtre ou au clavier,
jamais en argument (il resterait dans l'historique du terminal).
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import getpass
import hashlib
from pathlib import Path
import sys

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "upstream" / "src"))

from timecapsulesmb.integrations import acp  # noqa: E402

import cfb  # noqa: E402  (outils/, à côté de ce script)
import config  # noqa: E402
import motdepasse  # noqa: E402

SECRETS = {"raCr", "raWE", "raKT", "raGK", "raSe", "raS2"}  # raCA = canal automatique (booléen)


def cle_wpa(radio: dict, cle: str) -> None:
    """Met le mot de passe WPA d'une radio et sa clé dérivée.

    raWE contient la PSK WPA (PBKDF2-SHA1(mot de passe, SSID, 4096, 32)), calculée
    par l'Utilitaire AirPort, pas par l'appareil : wpa_supplicant et hostapd s'en
    servent telle quelle. Changer raNm ou raCr sans elle = poignée de main WPA2
    ratée (constaté le 30/10/2026)."""
    radio["raCr"] = cle
    radio["raWE"] = hashlib.pbkdf2_hmac("sha1", cle.encode(), radio["raNm"].encode(), 4096, 32)


def lire_wifi(hote: str, mdp: str) -> bytes:
    v = acp.get_properties(hote, mdp, ("WiFi",))["WiFi"]
    if isinstance(v, Exception):
        raise v
    return v


def ecrire_propriete(hote: str, mdp: str, nom: str, valeur: bytes) -> None:
    """SETPROP d'une valeur binaire (le client amont n'écrit que des entiers)."""
    payload = acp._compose_property_element(nom, valeur)
    sock = acp._send_message(hote, mdp, acp.COMMAND_SETPROP, payload, timeout=25.0)
    try:
        header = acp._read_reply_header(sock, expected_command=acp.COMMAND_SETPROP)
        if acp._read_property_results(sock, header) is None:
            acp._read_property_result(sock)
    finally:
        sock.close()


def sauvegarder(brut: bytes) -> Path:
    chemin = RACINE / "sauvegardes" / f"wifi-{dt.datetime.now():%Y%m%d-%H%M%S}.cfb"
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_bytes(brut)
    return chemin


def masque(o):
    if isinstance(o, dict):
        return {k: ("<masqué>" if k in SECRETS else masque(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [masque(x) for x in o]
    if isinstance(o, bytes):
        return o.hex()
    return o


def resume(conf: dict) -> str:
    lignes = []
    for i, r in enumerate(conf.get("radios", [])):
        role = {0: "point d'accès", 1: "CLIENT"}.get(r.get("raSt"), r.get("raSt"))
        lignes.append(f"radio {i} ({r.get('raMA', b'').hex() if isinstance(r.get('raMA'), bytes) else r.get('raMA')}) : "
                      f"{role}, SSID « {r.get('raNm')} », canal {r.get('raCh')}, sécurité {r.get('raWM')}, "
                      f"DWDS {r.get('dWDS')}, WDS classique {r.get('legacywds')}, invité {[v.get('Enabled') for v in r.get('vaps', [])]}")
    return "\n".join(lignes)


def ecarts(a, b, chemin="WiFi") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        return [e for k in sorted(set(a) | set(b), key=str) for e in ecarts(a.get(k), b.get(k), f"{chemin}.{k}")]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [e for i, (x, y) in enumerate(zip(a, b)) for e in ecarts(x, y, f"{chemin}[{i}]")]
    if a == b:
        return []
    cle = chemin.rsplit(".", 1)[-1]
    if cle in SECRETS:
        return [f"{chemin}: <masqué> -> <masqué>"]
    return [f"{chemin}: {a!r} -> {b!r}"]


def appliquer(hote: str, mdp: str, avant_brut: bytes, apres: dict, args) -> int:
    avant = cfb.lire(avant_brut)
    diff = ecarts(avant, apres)
    if not diff:
        print("Rien à changer.")
        return 0
    print("Changements prévus :")
    print("\n".join("  " + d for d in diff))
    copie = sauvegarder(avant_brut)
    print(f"Configuration actuelle sauvegardée : {copie}")
    print(f"Retour arrière : outils/tc-wifi.py restaurer {copie.relative_to(RACINE)}")
    if not args.oui and input("Écrire et redémarrer ? [o/N] ").strip().lower() != "o":
        print("Abandon, rien n'a été écrit.")
        return 1
    ecrire_propriete(hote, mdp, "WiFi", cfb.ecrire(apres))
    print("Configuration écrite.")
    if not args.sans_redemarrer:
        acp.reboot(hote, mdp)
        print("Redémarrage demandé (environ 1 à 2 minutes).")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--hote", help="défaut : TC_HOTE (config.local)")
    p.add_argument("--oui", action="store_true", help="ne pas demander confirmation")
    p.add_argument("--sans-redemarrer", action="store_true")
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("voir")
    c = sp.add_parser("client")
    c.add_argument("--radio", type=int, required=True, help="0 = 5 GHz, 1 = 2,4 GHz (d'après raMd/phymodes)")
    c.add_argument("--ssid", required=True)
    c.add_argument("--securite", type=int, help="valeur raWM du réseau à rejoindre (défaut : celle de la radio)")
    c.add_argument("--sans-dwds", action="store_true", help="client simple, sans WDS dynamique")
    a_ = sp.add_parser("point-acces")
    a_.add_argument("--radio", type=int, required=True)
    r = sp.add_parser("restaurer")
    r.add_argument("fichier", type=Path)
    args = p.parse_args()
    args.hote = args.hote or config.hote()

    mdp = motdepasse.obtenir()
    brut = lire_wifi(args.hote, mdp)
    conf = cfb.lire(brut)

    if args.cmd == "voir":
        print(resume(conf))
        return 0

    if args.cmd == "restaurer":
        cible = args.fichier.read_bytes()
        return appliquer(args.hote, mdp, brut, cfb.lire(cible), args)

    nouveau = copy.deepcopy(conf)
    radio = nouveau["radios"][args.radio]
    if args.cmd == "point-acces":
        radio["raSt"] = 0
    else:
        radio["raSt"] = 1
        radio["raNm"] = args.ssid
        if args.securite is not None:
            radio["raWM"] = args.securite
        if radio["raWM"] != 0:
            question = f"Mot de passe du réseau Wi-Fi « {args.ssid} » : "
            cle = (getpass.getpass(question) if sys.stdin.isatty()
                   else motdepasse.demander(question, masque=True))
            if not cle:
                raise SystemExit("Mot de passe Wi-Fi requis.")
            cle_wpa(radio, cle)
        radio["dWDS"] = not args.sans_dwds
    return appliquer(args.hote, mdp, brut, nouveau, args)


if __name__ == "__main__":
    sys.exit(main())
