"""Obtient un mot de passe d'appareil (Time Capsule, routeur OpenWrt…) sans jamais l'écrire sur disque.

Ordre : variable TC_PASSWORD, puis élément du trousseau macOS propre au projet
(service « time-capsule-seconde-vie »), puis fenêtre macOS à saisie masquée
(utile quand la commande tourne sans terminal, ex. préfixe « ! » de Claude
Code), puis saisie au clavier. La fenêtre propose de mémoriser le mot de passe
dans le trousseau ; « oublier » : security delete-generic-password -s time-capsule-seconde-vie
"""
from __future__ import annotations

import getpass
import os
import subprocess
import sys

SERVICE = "time-capsule-seconde-vie"
# appareil -> (compte du trousseau, libellé, variable d'environnement)
APPAREILS = {
    "time-capsule": ("time-capsule", "de la Time Capsule", "TC_PASSWORD"),
    "routeur": ("routeur-admin", "d'administration du routeur OpenWrt", "ROUTEUR_PASSWORD"),
}


def _trousseau(compte: str = "time-capsule") -> str | None:
    r = subprocess.run(["security", "find-generic-password", "-s", SERVICE, "-a", compte, "-w"],
                       capture_output=True, text=True)
    return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout else None


def _memoriser(mdp: str, compte: str = "time-capsule") -> None:
    subprocess.run(["security", "add-generic-password", "-U", "-s", SERVICE, "-a", compte,
                    "-l", f"{compte} (projet seconde vie)", "-w", mdp], capture_output=True)


def _fenetre(libelle: str = "de la Time Capsule", compte: str = "time-capsule") -> str | None:
    if sys.platform != "darwin":
        return None
    script = (f'set r to display dialog "Mot de passe {libelle} :" default answer "" with hidden answer '
              'with title "Time Capsule — seconde vie" buttons {"Annuler", "Une fois", "Mémoriser"} '
              'default button "Une fois" cancel button "Annuler"\n'
              'return (button returned of r) & linefeed & (text returned of r)')
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    bouton, _, mdp = r.stdout.rstrip("\n").partition("\n")
    if mdp and bouton == "Mémoriser":
        _memoriser(mdp, compte)
    return mdp or None


def _osa_texte(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def demander(question: str, masque: bool = False) -> str | None:
    """Fenêtre macOS de saisie (texte masqué si demandé) ; None si annulée."""
    if sys.platform != "darwin":
        return None
    script = (f'text returned of (display dialog "{_osa_texte(question)}" default answer "" '
              f'{"with hidden answer " if masque else ""}with title "Time Capsule — seconde vie")')
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return r.stdout.rstrip("\n") or None


def informer(message: str, boutons: tuple[str, ...] = ("OK",)) -> str | None:
    """Fenêtre macOS d'information ; renvoie le bouton choisi, None si annulée."""
    if sys.platform != "darwin":
        return None
    liste = ", ".join(f'"{_osa_texte(b)}"' for b in boutons)
    script = (f'button returned of (display dialog "{_osa_texte(message)}" buttons {{{liste}}} '
              f'default button "{_osa_texte(boutons[-1])}" with title "Time Capsule — seconde vie")')
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    return r.stdout.rstrip("\n") if r.returncode == 0 else None


def obtenir(appareil: str = "time-capsule") -> str:
    compte, libelle, variable = APPAREILS[appareil]
    mdp = os.environ.get(variable) or _trousseau(compte) or _fenetre(libelle, compte)
    if mdp:
        return mdp
    if sys.stdin.isatty():
        return getpass.getpass(f"Mot de passe {libelle} : ")
    raise SystemExit("Mot de passe non fourni (fenêtre annulée, pas de terminal).")
