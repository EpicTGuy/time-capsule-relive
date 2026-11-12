#!/usr/bin/env python3
"""Annote un pseudo-code Ghidra : chaque DAT_xxxxxxxx (mot d'un literal pool
ARM) est suivi de ce qu'il contient : constante 4 lettres, chaîne C, ou objet
clé ACPd (en-tête 0x756 suivi du nom).

    python3 analyse/annoter-pool.py <binaire ELF> <fichier.c> > annote.c
"""
from __future__ import annotations

import re
import struct
import sys


class Elf32:
    def __init__(self, path: str):
        self.d = open(path, "rb").read()
        phoff, = struct.unpack_from("<I", self.d, 28)
        phnum, = struct.unpack_from("<H", self.d, 44)
        self.segs = []
        for i in range(phnum):
            typ, off, va, _pa, fsz, *_ = struct.unpack_from("<8I", self.d, phoff + i * 32)
            if typ == 1:
                self.segs.append((va, off, fsz))

    def read(self, va: int, n: int) -> bytes | None:
        for start, off, size in self.segs:
            if start <= va < start + size:
                return self.d[off + va - start : off + va - start + n]
        return None

    def word(self, va: int) -> int | None:
        b = self.read(va, 4)
        return struct.unpack("<I", b)[0] if b and len(b) == 4 else None

    def cstr(self, va: int) -> str | None:
        b = self.read(va, 160)
        if not b:
            return None
        s = b.split(b"\0")[0]
        try:
            t = s.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return t if len(t) >= 2 and t.isprintable() else None

    def describe(self, va: int) -> str | None:
        v = self.word(va)
        if v is None:
            return None
        cc = struct.pack(">I", v)
        if v > 0x20000000 and all(48 <= c < 123 and chr(c).isalnum() for c in cc):
            return f"'{cc.decode()}'"
        hdr = self.read(v, 8)
        if hdr and hdr[:4] == b"\x56\x07\x00\x00":
            name = self.cstr(v + 8)
            if name:
                return f"clé {name}"
        s = self.cstr(v)
        if s:
            return '"' + s.replace("*/", "* /")[:80] + '"'
        if v < 0x10000:
            return str(v)
        return None


def main() -> int:
    elf = Elf32(sys.argv[1])
    text = open(sys.argv[2]).read()

    def sub(m: re.Match) -> str:
        desc = elf.describe(int(m.group(1), 16))
        return f"{m.group(0)}/*{desc}*/" if desc else m.group(0)

    sys.stdout.write(re.sub(r"DAT_([0-9a-f]{8})", sub, text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
