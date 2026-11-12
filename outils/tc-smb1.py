#!/usr/bin/env python3
"""Lit le disque d'une Time Capsule en SMB 1, en lecture seule, depuis un Mac
récent (macOS 27 n'a plus ni AFP ni SMB 1).

    .re-tools/venv/bin/python outils/tc-smb1.py lister [chemin]
    .re-tools/venv/bin/python outils/tc-smb1.py inventaire     # sauvegardes Time Machine
    .re-tools/venv/bin/python outils/tc-smb1.py copier <chemin distant> <dossier local>

Mot de passe : voir outils/motdepasse.py (variable, trousseau, fenêtre macOS).
Le fichier distant n'est jamais ouvert en écriture : seules les commandes
SMB de lecture (lister, ouvrir en lecture, lire) sont utilisées. La copie
reprend là où elle s'est arrêtée (fichiers déjà copiés à la bonne taille).
"""
from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
import plistlib
import sys
import time

from impacket.smb import FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_READ_DATA
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SessionError

import config  # outils/, à côté de ce script
import motdepasse

UTILISATEUR = "admin"  # la Time Capsule ignore le nom, seul le mot de passe compte


class Session:
    """Connexion SMB 1 qui se rouvre d'elle-même. Le serveur de la Time Capsule
    refuse par moments un nouvel accès au partage dans une session déjà
    utilisée (STATUS_BAD_NETWORK_NAME, observé le 28/10/2026) : on ouvre alors
    une session neuve et on recommence l'opération entière."""

    ESSAIS = 4

    def __init__(self, hote: str):
        self.hote = hote
        self.c = self._ouvrir()

    def _ouvrir(self) -> SMBConnection:
        c = SMBConnection(self.hote, self.hote, preferredDialect=SMB_DIALECT, timeout=60)
        c.login(UTILISATEUR, motdepasse.obtenir())
        return c

    def appel(self, operation):
        for essai in range(self.ESSAIS):
            try:
                return operation(self.c)
            except (SessionError, OSError, NetBIOSError):
                if essai == self.ESSAIS - 1:
                    raise
                try:
                    self.c.close()
                except Exception:
                    pass
                time.sleep(1 + essai * 2)
                self.c = self._ouvrir()

    def fermer(self) -> None:
        try:
            self.c.logoff()
        except Exception:
            pass


def connexion(hote: str) -> Session:
    return Session(hote)


def partage_disque(c: Session) -> str:
    noms = [s["shi1_netname"][:-1] for s in c.appel(lambda smb: smb.listShares())]
    candidats = [n for n in noms if not n.endswith("$")]
    print("partages :", ", ".join(noms))
    return candidats[0]


def lister(c: Session, partage: str, chemin: str) -> list:
    motif = (chemin.rstrip("/") + "/*") if chemin else "*"
    return [f for f in c.appel(lambda smb: smb.listPath(partage, motif)) if f.get_longname() not in (".", "..")]


def taille_dossier(c: SMBConnection, partage: str, chemin: str) -> tuple[int, int]:
    total, n = 0, 0
    for f in lister(c, partage, chemin):
        sous = f"{chemin}/{f.get_longname()}"
        if f.is_directory():
            t, k = taille_dossier(c, partage, sous)
            total, n = total + t, n + k
        else:
            total, n = total + f.get_filesize(), n + 1
    return total, n


MORCEAU = 60 * 1024  # SMB 1 : lectures de 60 Kio au plus par requête


def _lire(smb: SMBConnection, partage: str, chemin: str) -> bytes:
    """Lecture seule (FILE_READ_DATA, partage autorisé), arbre et fichier ouverts
    à la main : getFile d'impacket échoue plus souvent sur la Time Capsule."""
    tid = smb.connectTree(partage)
    try:
        fid = smb.openFile(tid, chemin.replace("/", "\\"), desiredAccess=FILE_READ_DATA,
                           shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE)
        morceaux, total = [], 0
        try:
            while bloc := smb.readFile(tid, fid, total, MORCEAU):
                morceaux.append(bloc)
                total += len(bloc)
        finally:
            smb.closeFile(tid, fid)
    finally:
        smb.disconnectTree(tid)
    return b"".join(morceaux)


def lire_vers(c: Session, partage: str, chemin: str, ecrire) -> int:
    """Lit tout le fichier (128 Mo au plus pour une bande) puis le passe à
    `ecrire` : en cas de reprise de session, rien de partiel n'est écrit."""
    data = c.appel(lambda smb: _lire(smb, partage, chemin))
    ecrire(data)
    return len(data)


def lire_fichier(c: Session, partage: str, chemin: str) -> bytes:
    return c.appel(lambda smb: _lire(smb, partage, chemin))


def go(o: int) -> str:
    return f"{o / 1e9:.1f} Go"


def cmd_lister(c, partage, chemin):
    for f in lister(c, partage, chemin):
        genre = "d" if f.is_directory() else "f"
        date = time.strftime("%Y-%m-%d %H:%M", time.localtime(f.get_mtime_epoch()))
        print(f"{genre} {f.get_filesize():>15} {date} {f.get_longname()}")


def cmd_inventaire(c, partage):
    for f in lister(c, partage, ""):
        nom = f.get_longname()
        if not nom.endswith((".sparsebundle", ".backupbundle")):
            continue
        print(f"\n== {nom}")
        for meta in ("com.apple.TimeMachine.MachineID.plist", "com.apple.TimeMachine.SnapshotHistory.plist",
                     "Info.plist"):
            try:
                p = plistlib.loads(lire_fichier(c, partage, f"{nom}/{meta}"))
            except Exception as exc:
                print(f"   {meta} : illisible ({type(exc).__name__})")
                continue
            if meta.endswith("SnapshotHistory.plist"):
                snaps = p.get("Snapshots", [])
                dates = [str(s.get("com.apple.backupd.SnapshotCompletionDate", "?")) for s in snaps]
                print(f"   {len(snaps)} sauvegardes, première {dates[0] if dates else '-'}, dernière {dates[-1] if dates else '-'}")
            elif meta.endswith("MachineID.plist"):
                print(f"   Mac : {p.get('com.apple.backupd.HostUUID', '?')} modèle {p.get('com.apple.backupd.ModelID', '?')}")
            else:
                print(f"   bandes de {p.get('band-size', 0) // 1048576} Mo, taille virtuelle {go(p.get('size', 0))}")
        t, n = taille_dossier(c, partage, f"{nom}/bands")
        print(f"   occupation réelle : {go(t)} ({n} bandes)")


def _a_copier(c, partage, src: str, dst: Path, liste: list) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for f in lister(c, partage, src):
        s, d = f"{src}/{f.get_longname()}", dst / f.get_longname()
        if f.is_directory():
            _a_copier(c, partage, s, d, liste)
        elif not (d.exists() and d.stat().st_size == f.get_filesize()):
            liste.append((s, d, f.get_filesize()))


def cmd_copier(c, partage, distant, local: Path, hote: str, fils: int):
    """Copie reprenable, avec `fils` connexions SMB en parallèle : en SMB 1
    chaque lecture attend sa réponse, le débit d'une seule connexion est donc
    borné par la latence (~7 Mo/s mesurés)."""
    import queue
    import threading

    racine = local / Path(distant.rstrip("/")).name
    liste: list = []
    _a_copier(c, partage, distant.rstrip("/"), racine, liste)
    total = sum(t for _, _, t in liste)
    print(f"{len(liste)} fichiers à copier, {go(total)}, {fils} connexions", flush=True)
    travail: queue.Queue = queue.Queue()
    for element in sorted(liste, key=lambda e: -e[2]):
        travail.put(element)
    fait, erreurs, verrou = [0], [], threading.Lock()

    def ouvrier():
        conn = connexion(hote)
        while True:
            try:
                s, d, taille = travail.get_nowait()
            except queue.Empty:
                break
            tmp = d.with_name(d.name + ".partiel")
            try:
                with open(tmp, "wb") as out:
                    lire_vers(conn, partage, s, out.write)
                if tmp.stat().st_size != taille:
                    raise OSError(f"taille {tmp.stat().st_size} au lieu de {taille}")
                tmp.rename(d)
                with verrou:
                    fait[0] += taille
            except Exception as exc:
                with verrou:
                    erreurs.append(f"{s} : {exc}")
                try:  # connexion peut-être cassée : on en rouvre une
                    conn = connexion(hote)
                except Exception:
                    break
        conn.fermer()

    debut = time.time()
    threads = [threading.Thread(target=ouvrier, daemon=True) for _ in range(fils)]
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        time.sleep(30)
        ecoule = time.time() - debut
        debit = fait[0] / ecoule if ecoule else 0
        reste = (total - fait[0]) / debit if debit else 0
        print(f"{dt.datetime.now():%H:%M} {go(fait[0])} / {go(total)} — {debit / 1e6:.1f} Mo/s — "
              f"reste ≈ {reste / 3600:.1f} h — {len(erreurs)} erreur(s)", flush=True)
    for e in erreurs:
        print("ERREUR", e, flush=True)
    print("copie terminée" if not erreurs else "copie incomplète : relancer la même commande pour reprendre",
          flush=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--hote", help="défaut : TC_HOTE (config.local)")
    sp = p.add_subparsers(dest="cmd", required=True)
    l = sp.add_parser("lister"); l.add_argument("chemin", nargs="?", default="")
    sp.add_parser("inventaire")
    k = sp.add_parser("copier"); k.add_argument("distant"); k.add_argument("local", type=Path)
    k.add_argument("--fils", type=int, default=6, help="connexions parallèles")
    a = p.parse_args()
    a.hote = a.hote or config.hote()
    c = connexion(a.hote)
    partage = partage_disque(c)
    if a.cmd == "lister":
        cmd_lister(c, partage, a.chemin)
    elif a.cmd == "inventaire":
        cmd_inventaire(c, partage)
    else:
        cmd_copier(c, partage, a.distant, a.local, a.hote, a.fils)
    c.fermer()
    return 0


if __name__ == "__main__":
    sys.exit(main())
