#!/usr/bin/env python3
"""Extrait une image FFS v1 (UFS1, petit-boutiste) de NetBSD vers un dossier.

    python3 outils/ffs1-extraire.py <image> <dossier> [--decalage 0x5616e0]

Le noyau NetBSD de la Time Capsule embarque son système de fichiers racine
(« md_root ») au milieu de l'image décompressée ; --decalage indique où il
commence. Sans --decalage, l'outil cherche le superbloc lui-même.
Lecture seule sur l'image ; n'écrit que dans le dossier de sortie.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import struct
import sys

FS_UFS1_MAGIC = 0x011954
SBLOCK = 8192
MAGIC_OFF = 1372
DINODE_SIZE = 128
ROOT_INO = 2


class FFS1:
    def __init__(self, data: bytes, base: int):
        self.d = data
        self.base = base
        sb = data[base + SBLOCK : base + SBLOCK + 2048]
        if struct.unpack_from("<i", sb, MAGIC_OFF)[0] != FS_UFS1_MAGIC:
            raise ValueError(f"pas de superbloc UFS1 à {base:#x}")
        u = lambda off: struct.unpack_from("<i", sb, off)[0]
        self.iblkno = u(16)
        self.cgoffset, self.cgmask = u(24), u(28)
        self.ncg, self.bsize, self.fsize, self.frag = u(44), u(48), u(52), u(56)
        self.nindir, self.inopb = u(116), u(120)
        self.ipg, self.fpg = u(184), u(188)
        # Le motif magique apparaît aussi dans le code du noyau : on vérifie
        # que la géométrie a du sens avant d'y croire.
        sane = (self.bsize in (4096, 8192, 16384, 32768, 65536)
                and self.fsize * self.frag == self.bsize
                and 0 < self.ncg < 10000 and self.ipg > 0 and self.fpg > 0 and self.inopb > 0)
        if not sane:
            raise ValueError(f"géométrie incohérente à {base:#x}")

    def info(self) -> str:
        return (f"bsize {self.bsize}, fsize {self.fsize}, ncg {self.ncg}, "
                f"ipg {self.ipg}, fpg {self.fpg}, inopb {self.inopb}")

    def frag_bytes(self, fragno: int, length: int) -> bytes:
        off = self.base + fragno * self.fsize
        return self.d[off : off + length]

    def inode(self, ino: int) -> bytes:
        cg, idx = divmod(ino, self.ipg)
        cgstart = self.fpg * cg + self.cgoffset * (cg & ~self.cgmask)
        fragno = cgstart + self.iblkno + (idx // self.inopb) * self.frag
        off = self.base + fragno * self.fsize + (idx % self.inopb) * DINODE_SIZE
        return self.d[off : off + DINODE_SIZE]

    def _indirect(self, blk: int, level: int) -> list[int]:
        if blk == 0:
            return [0] * (self.nindir ** (level + 1))
        ptrs = struct.unpack(f"<{self.nindir}i", self.frag_bytes(blk, self.bsize))
        if level == 0:
            return list(ptrs)
        out: list[int] = []
        for p in ptrs:
            out.extend(self._indirect(p, level - 1))
        return out

    def read(self, ino: int) -> tuple[int, bytes]:
        di = self.inode(ino)
        mode = struct.unpack_from("<H", di, 0)[0]
        size = struct.unpack_from("<Q", di, 8)[0]
        if stat.S_ISLNK(mode) and size < 60:  # lien court rangé dans l'inode
            return mode, di[40 : 40 + size]
        direct = list(struct.unpack_from("<12i", di, 40))
        ind = struct.unpack_from("<3i", di, 88)
        nblocks = -(-size // self.bsize)
        blocks = direct
        for level, ptr in enumerate(ind):
            if len(blocks) >= nblocks:
                break
            blocks += self._indirect(ptr, level)
        chunks = []
        for b in blocks[:nblocks]:
            chunks.append(b"\0" * self.bsize if b == 0 else self.frag_bytes(b, self.bsize))
        return mode, b"".join(chunks)[:size]

    def listdir(self, ino: int) -> list[tuple[str, int]]:
        _, data = self.read(ino)
        entries, off = [], 0
        while off + 8 <= len(data):
            d_ino, reclen, _typ, namlen = struct.unpack_from("<IHBB", data, off)
            if reclen == 0:
                off = (off // 512 + 1) * 512
                continue
            if d_ino:
                name = data[off + 8 : off + 8 + namlen].decode("utf-8", "replace")
                if name not in (".", ".."):
                    entries.append((name, d_ino))
            off += reclen
        return entries


def find_base(data: bytes) -> int:
    pat = struct.pack("<i", FS_UFS1_MAGIC)
    i = data.find(pat)
    while i >= 0:
        base = i - MAGIC_OFF - SBLOCK
        if base >= 0:
            try:
                FFS1(data, base)
                return base
            except ValueError:
                pass
        i = data.find(pat, i + 1)
    raise SystemExit("aucun superbloc UFS1 trouvé")


def extract(fs: FFS1, ino: int, dest: Path, inventaire: list[str], rel: str = "") -> None:
    for name, child in fs.listdir(ino):
        mode, data = fs.read(child)
        path = dest / name
        relpath = f"{rel}/{name}"
        if stat.S_ISDIR(mode):
            path.mkdir(exist_ok=True)
            inventaire.append(f"d {oct(mode & 0o7777)} {relpath}/")
            extract(fs, child, path, inventaire, relpath)
        elif stat.S_ISLNK(mode):
            target = data.decode("utf-8", "replace")
            if path.is_symlink() or path.exists():
                path.unlink()
            os.symlink(target, path)
            inventaire.append(f"l {relpath} -> {target}")
        elif stat.S_ISREG(mode):
            path.write_bytes(data)
            path.chmod(mode & 0o755 | 0o600)
            inventaire.append(f"f {oct(mode & 0o7777)} {len(data):>9} {relpath}")
        else:
            inventaire.append(f"? {oct(mode)} {relpath}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("image", type=Path)
    p.add_argument("dossier", type=Path)
    p.add_argument("--decalage", type=lambda s: int(s, 0))
    a = p.parse_args()
    data = a.image.read_bytes()
    base = a.decalage if a.decalage is not None else find_base(data)
    fs = FFS1(data, base)
    print(f"FFS1 à {base:#x} : {fs.info()}")
    a.dossier.mkdir(parents=True, exist_ok=True)
    inventaire: list[str] = []
    extract(fs, ROOT_INO, a.dossier, inventaire)
    (a.dossier.parent / f"{a.dossier.name}.inventaire.txt").write_text("\n".join(inventaire) + "\n")
    print(f"{len(inventaire)} entrées extraites dans {a.dossier}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
