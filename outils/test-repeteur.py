#!/usr/bin/env python3
"""Test guidé du répéteur : une radio de la Time Capsule devient client Wi-Fi
(DWDS) du routeur principal, l'autre reste point d'accès.

    .re-tools/venv/bin/python outils/test-repeteur.py --radio 1

Déroulé (fenêtres macOS pour les gestes physiques) :
  1. sauvegarde exacte de la configuration Wi-Fi (sauvegardes/wifi-….cfb) ;
  2. nom et mot de passe du Wi-Fi principal demandés par fenêtre ;
  3. écriture + redémarrage, puis on débranche le câble Ethernet de la
     Time Capsule (câble + Wi-Fi vers le même routeur = boucle réseau) ;
  4. attente : revient-elle sur le réseau par le Wi-Fi seul ? En mode client,
     elle prend une autre adresse (bail DHCP lié à la MAC de la radio) : on la
     cherche par Bonjour et par ses MAC, pas seulement à son adresse habituelle ;
  5. si oui : relevé ACP complet, test d'un appareil derrière elle, puis
     retour à l'état d'origine (sauf si on choisit de garder le mode) ;
     si non : on rebranche le câble, relevé (journal système compris),
     restauration vérifiée.
Journal : sauvegardes/test-repeteur-AAAAMMJJ-HHMM.log

Leçon du test n° 1 (28/10/2026) : canal laissé à 36 alors que le routeur OpenWrt émet
sur 108 → problème « raNN », jamais associée. D'où --canal.
Leçon des tests n° 3 à 5 (30/10/2026) : raWE (PSK dérivée) doit être recalculée
avec le SSID et le mot de passe, sinon la poignée de main WPA2 échoue.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "outils"))
sys.path.insert(0, str(RACINE / "upstream" / "src"))

import cfb  # noqa: E402
import config  # noqa: E402
import motdepasse  # noqa: E402
from timecapsulesmb.integrations import acp  # noqa: E402


def _module(nom: str, fichier: str):
    spec = importlib.util.spec_from_file_location(nom, RACINE / "outils" / fichier)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


tcwifi = _module("tcwifi", "tc-wifi.py")
acplire = _module("acplire", "acp-lire.py")

HOTE_HABITUEL = config.hote()
JOURNAL = RACINE / "sauvegardes" / f"test-repeteur-{dt.datetime.now():%Y%m%d-%H%M}.log"


def log(msg: str) -> None:
    ligne = f"{dt.datetime.now():%H:%M:%S} {msg}"
    print(ligne, flush=True)
    with open(JOURNAL, "a") as f:
        f.write(ligne + "\n")


def acp_ouvert(ip: str) -> bool:
    return subprocess.run(["nc", "-z", "-G", "2", ip, "5009"], capture_output=True).returncode == 0


def ip_bonjour(nom_bonjour: str) -> str | None:
    try:
        r = subprocess.run(["dns-sd", "-G", "v4", nom_bonjour], capture_output=True, text=True, timeout=3)
        sortie = r.stdout
    except subprocess.TimeoutExpired as exc:
        sortie = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", sortie.split("Hostname", 1)[-1])
    return m.group(1) if m else None


def ip_par_mac(macs: set[str]) -> str | None:
    reseau = HOTE_HABITUEL.rsplit(".", 1)[0]
    subprocess.run(["ping", "-c", "1", "-t", "1", f"{reseau}.255"], capture_output=True)
    for ligne in subprocess.run(["arp", "-an"], capture_output=True, text=True).stdout.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", ligne)
        if m and ":".join(f"{int(x, 16):02x}" for x in m.group(2).split(":")) in macs:
            return m.group(1)
    return None


NOM_BONJOUR = ""  # rempli au démarrage depuis le nom de l'appareil (syNm)


def trouver(macs: set[str]) -> str | None:
    """Adresse où ACP répond, quelle que soit l'adresse prise par la Time Capsule."""
    for ip in (HOTE_HABITUEL, ip_bonjour(NOM_BONJOUR) if NOM_BONJOUR else None, ip_par_mac(macs)):
        if ip and acp_ouvert(ip):
            return ip
    return None


def attendre_absente(macs: set[str], delai: int) -> None:
    fin = time.time() + delai
    while time.time() < fin and trouver(macs):
        time.sleep(3)


def attendre_presente(macs: set[str], delai: int, mdp: str) -> str | None:
    fin, dernier = time.time() + delai, None
    while time.time() < fin:
        ip = trouver(macs)
        if ip:
            try:
                st = cfb.lire(acp.get_properties(ip, mdp, ("sySt",))["sySt"])
                problemes = [p.get("code") for p in st.get("problems", [])]
            except Exception as exc:  # démon pas encore prêt
                problemes = [f"lecture impossible ({type(exc).__name__})"]
            if problemes != dernier:
                log(f"joignable en {ip}, problèmes signalés : {problemes or 'aucun'}")
                dernier = problemes
            if not problemes:
                return ip
        time.sleep(5)
    return None


def reseaux_vus(ip: str, mdp: str) -> list[dict]:
    """Résultats du dernier scan Wi-Fi de la Time Capsule (propriété raSR)."""
    brut = acp.get_properties(ip, mdp, ("raSR",))["raSR"]
    if isinstance(brut, Exception):
        return []
    # scan_results = [{"wlan0": [réseau, …]}, …] : une entrée par interface
    return [r for par_interface in cfb.lire(brut).get("scan_results", [])
            for liste in par_interface.values() for r in liste]


def canal_du_reseau(ip: str, mdp: str, ssid: str, radio: dict) -> int | None:
    """Canal où la Time Capsule voit `ssid`, sur la bande de cette radio (None si absent)."""
    bande_24 = radio.get("raCh", 0) <= 14
    canaux = [r.get("CHANNEL") for r in reseaux_vus(ip, mdp)
              if r.get("SSID_STR") == ssid and isinstance(r.get("CHANNEL"), int)
              and (r["CHANNEL"] <= 14) == bande_24]
    return canaux[0] if canaux else None


def releve(ip: str, mdp: str, etiquette: str) -> None:
    props = acplire.lire(ip, mdp)
    props.pop("syPW", None)
    chemin = RACINE / "sauvegardes" / f"acp-{dt.datetime.now():%Y%m%d-%H%M}-{etiquette}.json"
    chemin.write_text(json.dumps({"hote": ip, "date": dt.datetime.now().isoformat(), "proprietes": props},
                                 indent=1, ensure_ascii=False))
    log(f"relevé ACP : {chemin.name}")


def restaurer(ip: str, mdp: str, origine: bytes, macs: set[str]) -> bool:
    log(f"restauration de la configuration d'origine (via {ip})")
    tcwifi.ecrire_propriete(ip, mdp, "WiFi", origine)
    acp.reboot(ip, mdp)
    attendre_absente(macs, 90)
    nouvelle = attendre_presente(macs, 300, mdp)
    if not nouvelle:
        log("ÉCHEC : la Time Capsule ne revient pas après restauration")
        return False
    identique = tcwifi.lire_wifi(nouvelle, mdp) == origine
    log(f"de retour en {nouvelle}, configuration {'IDENTIQUE' if identique else 'DIFFÉRENTE'} de l'origine")
    return identique


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--radio", type=int, default=1, help="radio passée en client (0 = 5 GHz, 1 = 2,4 GHz)")
    p.add_argument("--canal", type=int, help="forcer le canal (raCh) ; défaut : celui où le réseau est vu")
    p.add_argument("--sans-dwds", action="store_true")
    p.add_argument("--delai", type=int, default=180,
                   help="attente du retour par le Wi-Fi, en secondes (défaut 180 : redémarrage ~50 s + association)")
    a = p.parse_args()
    JOURNAL.parent.mkdir(parents=True, exist_ok=True)

    mdp = motdepasse.obtenir()
    ip = HOTE_HABITUEL
    origine = tcwifi.lire_wifi(ip, mdp)
    copie = tcwifi.sauvegarder(origine)
    log(f"configuration d'origine sauvegardée : {copie.name}")
    conf = cfb.lire(origine)
    # MAC Ethernet (waMA) et des radios : la Time Capsule change d'adresse IP en mode client
    ident = acp.get_properties(ip, mdp, ("waMA", "syNm"))
    global NOM_BONJOUR
    NOM_BONJOUR = ident["syNm"].rstrip(b"\0").decode().replace(" ", "-") + ".local"
    macs = {ident["waMA"].hex(":")} | {
        (r["raMA"].hex(":") if isinstance(r.get("raMA"), bytes) else str(r.get("raMA"))).lower()
        for r in conf["radios"]}

    ssid = motdepasse.demander("Nom exact du Wi-Fi principal à rejoindre :")
    if not ssid:
        log("abandon : nom du Wi-Fi non fourni")
        return 1
    cle = motdepasse.demander(f"Mot de passe du Wi-Fi « {ssid} » :", masque=True)
    if not cle:
        log("abandon : mot de passe Wi-Fi non fourni")
        return 1

    radio = conf["radios"][a.radio]
    vu = canal_du_reseau(ip, mdp, ssid, radio)
    if vu is None:
        bande = "2,4 GHz" if radio.get("raCh", 0) <= 14 else "5 GHz"
        noms = sorted({r.get("SSID_STR") for r in reseaux_vus(ip, mdp) if r.get("SSID_STR")})
        log(f"abandon : « {ssid} » non vu sur la bande {bande} de la radio {a.radio} ; réseaux vus : {noms}")
        motdepasse.informer(f"« {ssid} » n'est pas visible en {bande} par cette radio. Rien n'a été modifié.\n\n"
                            f"Réseaux vus : {', '.join(noms)}")
        return 1
    radio.update({"raSt": 1, "raNm": ssid, "dWDS": not a.sans_dwds})
    tcwifi.cle_wpa(radio, cle)
    radio["raCh"] = a.canal if a.canal is not None else vu
    log(f"changements : {tcwifi.ecarts(cfb.lire(origine), conf)}")

    if motdepasse.informer(
            "Allez près de la Time Capsule.\n\nDès que vous cliquez sur « Prêt », je change le réglage et elle "
            "redémarre. Une deuxième fenêtre vous dira alors de débrancher son câble Ethernet "
            "(PAS l'alimentation).", ("Annuler", "Prêt")) != "Prêt":
        log("abandon avant écriture : rien n'a été modifié")
        return 1

    tcwifi.ecrire_propriete(ip, mdp, "WiFi", cfb.ecrire(conf))
    acp.reboot(ip, mdp)
    log(f"écrit : radio {a.radio} en client de « {ssid} » (canal {radio.get('raCh')}, DWDS {radio['dWDS']}) ; "
        "redémarrage demandé")
    motdepasse.informer("Débranchez MAINTENANT le câble Ethernet de la Time Capsule, puis cliquez OK.\n\n"
                        "Le voyant peut clignoter 1 à 2 minutes : c'est normal.")
    log("câble débranché (confirmé)")
    attendre_absente(macs, 60)

    log(f"attente du retour par le Wi-Fi seul ({a.delai} s max)")
    ip = attendre_presente(macs, a.delai, mdp)
    if ip:
        log(f"SUCCÈS ÉTAPE 1 : joignable SANS câble en {ip}, aucun problème signalé")
        releve(ip, mdp, "repeteur")
        rep = motdepasse.informer(
            "Elle a rejoint le Wi-Fi principal !\n\nTest 2 : connectez votre téléphone au Wi-Fi "
            "« AirPort Time Capsule Wi-Fi » (oubliez d'abord le Wi-Fi principal si besoin) et ouvrez une page web.",
            ("Internet ne marche pas", "Internet marche"))
        log(f"appareil derrière la Time Capsule : {rep}")
        choix = motdepasse.informer("Garder ce mode répéteur ou revenir à l'état d'origine ?",
                                    ("Garder le répéteur", "Revenir à l'origine"))
        if choix == "Garder le répéteur":
            log("mode répéteur conservé à la demande de l'utilisateur")
            log(f"retour arrière plus tard : outils/tc-wifi.py --hote {ip} restaurer sauvegardes/{copie.name}")
            return 0
        ok = restaurer(ip, mdp, origine, macs)
        motdepasse.informer("Configuration d'origine remise. Vous pouvez rebrancher le câble Ethernet.")
        log("fin : câble à rebrancher (demandé)")
        return 0 if ok else 2

    log(f"ÉCHEC ÉTAPE 1 : pas de lien Wi-Fi sans câble en {a.delai} s")
    motdepasse.informer("Le lien Wi-Fi ne s'est pas établi.\n\nRebranchez le câble Ethernet de la "
                        "Time Capsule, puis cliquez OK : je relève ses journaux et remets la configuration d'origine.")
    log("câble rebranché (confirmé)")
    fin = time.time() + 240
    while time.time() < fin and not (ip := trouver(macs)):
        time.sleep(5)
    if not ip:
        log("ÉCHEC : injoignable même avec le câble ; secours : reset doux (bouton 1 s) puis restaurer")
        return 3
    log(f"joignable par le câble en {ip}")
    releve(ip, mdp, "echec")
    ok = restaurer(ip, mdp, origine, macs)
    motdepasse.informer("Test terminé : configuration d'origine remise." if ok
                        else "Attention : la restauration n'a pas pu être vérifiée, voir le journal.")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
