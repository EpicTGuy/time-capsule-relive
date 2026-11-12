"""Format « CFB0 » d'Apple (cflbinary) : listes de propriétés compactes utilisées
par ACP (WiFi, raSL, raSR…). Port Python 3 de airpyrt-tools (x56), avec les
dates en plus.

Codage : « CFB0 » + un objet + « END! ». Marqueur sur un octet, type dans le
quartet haut : 0x00 nul (et fin de liste) / 0x08 faux / 0x09 vrai,
0x1n entier gros-boutiste de 2^n octets, 0x2n réel, 0x33 date (réel 8 octets,
secondes depuis 2001), 0x4n données (n < 15 = longueur, sinon entier suivant),
0x70 texte UTF-8 terminé par un nul, 0xA0 tableau et 0xD0 dictionnaire
terminés par un nul.
"""
from __future__ import annotations

import datetime as dt
import struct

ENTETE, PIED = b"CFB0", b"END!"
_EPOCH_2001 = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)


class CFBError(ValueError):
    pass


class _Lecteur:
    def __init__(self, data: bytes):
        self.d, self.i = data, 0

    def octets(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise CFBError("données tronquées")
        b = self.d[self.i : self.i + n]
        self.i += n
        return b

    def entier(self, exp: int) -> int:
        taille = 1 << exp
        if taille not in (1, 2, 4, 8):
            raise CFBError(f"entier de {taille} octets")
        return int.from_bytes(self.octets(taille), "big")

    def compte(self, info: int) -> int:
        if info < 0xF:
            return info
        m = self.octets(1)[0]
        if m & 0xF0 != 0x10:
            raise CFBError("longueur attendue")
        return self.entier(m & 0x0F)

    def objet(self):
        m = self.octets(1)[0]
        t, info = m & 0xF0, m & 0x0F
        if t == 0x00:
            return {0: None, 8: False, 9: True}.get(info) if info in (0, 8, 9) else self._inconnu(m)
        if t == 0x10:
            return self.entier(info)
        if t == 0x20:
            return struct.unpack(">f" if info == 2 else ">d", self.octets(1 << info))[0]
        if t == 0x30:
            s = struct.unpack(">d", self.octets(8))[0]
            return _EPOCH_2001 + dt.timedelta(seconds=s)
        if t == 0x40:
            return self.octets(self.compte(info))
        if t == 0x70:
            fin = self.d.index(b"\0", self.i)
            s = self.d[self.i : fin].decode("utf-8")
            self.i = fin + 1
            return s
        if t == 0xA0:
            liste = []
            while (o := self.objet()) is not None:
                liste.append(o)
            return liste
        if t == 0xD0:
            dico = {}
            while (k := self.objet()) is not None:
                dico[k] = self.objet()
            return dico
        return self._inconnu(m)

    @staticmethod
    def _inconnu(m: int):
        raise CFBError(f"marqueur non géré {m:#04x}")


def lire(data: bytes):
    if data[:4] != ENTETE or data[-4:] != PIED:
        raise CFBError("pas un CFB0")
    lec = _Lecteur(data[4:-4])
    obj = lec.objet()
    if lec.i != len(lec.d):
        raise CFBError("données en trop après l'objet racine")
    return obj


def _ecrire(o) -> bytes:
    if o is None:
        return b"\x00"
    if o is True:
        return b"\x09"
    if o is False:
        return b"\x08"
    if isinstance(o, int):
        for exp, fmt in ((0, ">B"), (1, ">H"), (2, ">I"), (3, ">Q")):
            if o < 1 << (8 << exp):
                return bytes([0x10 | exp]) + struct.pack(fmt, o)
        raise CFBError("entier trop grand")
    if isinstance(o, float):
        return b"\x23" + struct.pack(">d", o)
    if isinstance(o, dt.datetime):
        return b"\x33" + struct.pack(">d", (o - _EPOCH_2001).total_seconds())
    if isinstance(o, (bytes, bytearray)):
        n = len(o)
        return (bytes([0x40 | n]) if n < 0xF else b"\x4f" + _ecrire(n)) + bytes(o)
    if isinstance(o, str):
        return b"\x70" + o.encode("utf-8") + b"\x00"
    if isinstance(o, (list, tuple)):
        return b"\xa0" + b"".join(_ecrire(e) for e in o) + b"\x00"
    if isinstance(o, dict):
        return b"\xd0" + b"".join(_ecrire(k) + _ecrire(v) for k, v in o.items()) + b"\x00"
    raise CFBError(f"type non géré : {type(o).__name__}")


def ecrire(obj) -> bytes:
    return ENTETE + _ecrire(obj) + PIED
