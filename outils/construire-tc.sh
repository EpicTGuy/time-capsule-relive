#!/usr/bin/env bash
#
# Construit les programmes Go pour la Time Capsule (NetBSD 6, ARM) :
#   binaires/wg-tc     WireGuard en espace utilisateur (wireguard-go + gVisor netstack)
#   binaires/tc-swap   activation d'un fichier d'échange (swapctl)
#   binaires/relive    interface web d'administration ReLive
#   binaires/tc-dhcp   client DHCP du mode relais (Wi-Fi client, par BPF)
#   binaires/tc-pont   pile TCP/IP sur le Wi-Fi client (gVisor, par BPF), relais vers les services locaux
#
#   ./outils/construire-tc.sh
#
# Le Go officiel ne tourne pas tel quel sur le NetBSD 6 d'Apple. Correctifs
# (analyse/go-netbsd6-timecapsule.patch) :
#   - ucontext : uc_mcontext à l'octet 36 (pas de remplissage EABI) → création de threads ;
#   - _lwp_park : ___lwp_park60 absent, ___lwp_park50 (échéance absolue) à la place.
# wireguard-go : le paquet ipc exclut NetBSD (analyse/wireguard-go-netbsd.patch).
# x/crypto : Poly1305 en limbes de 26 bits sur processeurs 32 bits, ×2 environ sur
# la Time Capsule (analyse/x-crypto-poly1305-32bit.patch).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/.re-tools"
GO_VER="go1.27.3"
WG_VER="v0.0.0-20261024220952-b3bc704ef0ee"
XC_VER="v0.37.0"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# 1. Go officiel (vérifié par somme SHA-256), puis copie corrigée
if [ ! -x "$T/go/bin/go" ]; then
  F="$GO_VER.darwin-arm64.tar.gz"
  SHA=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" | python3 -c \
    "import json,sys;print(next(f['sha256'] for r in json.load(sys.stdin) for f in r['files'] if f['filename']=='$F'))")
  mkdir -p "$T/dl"; curl -fsSL -o "$T/dl/$F" "https://go.dev/dl/$F"
  echo "$SHA  $T/dl/$F" | shasum -a 256 -c -
  tar -xzf "$T/dl/$F" -C "$T"
fi
if [ ! -x "$T/go-tc/bin/go" ]; then
  log "Go corrigé pour NetBSD 6"
  rm -rf "$T/go-tc"; cp -R "$T/go" "$T/go-tc"
  patch -d "$T/go-tc" -p1 < "$ROOT/analyse/go-netbsd6-timecapsule.patch"
fi
export GOROOT="$T/go-tc" PATH="$T/go-tc/bin:$PATH" CGO_ENABLED=0 GOOS=netbsd GOARCH=arm GOARM=7

# 2. wireguard-go corrigé (module local, référencé par outils/wg-tc/go.mod)
if [ ! -d "$T/wireguard-go-tc" ]; then
  log "wireguard-go $WG_VER"
  (cd "$ROOT/outils/wg-tc" && GOOS= GOARCH= go mod download golang.zx2c4.com/wireguard@"$WG_VER")
  SRC=$(cd "$ROOT/outils/wg-tc" && GOOS= GOARCH= go list -m -f '{{.Dir}}' golang.zx2c4.com/wireguard@"$WG_VER")
  cp -R "$SRC" "$T/wireguard-go-tc"; chmod -R u+w "$T/wireguard-go-tc"
  patch -d "$T/wireguard-go-tc" -p1 < "$ROOT/analyse/wireguard-go-netbsd.patch"
fi

# 3. x/crypto corrigé (Poly1305 32 bits), référencé par outils/wg-tc/go.mod
if [ ! -d "$T/x-crypto-tc" ]; then
  log "x/crypto $XC_VER (Poly1305 32 bits)"
  (cd "$ROOT/outils/wg-tc" && GOOS= GOARCH= go mod download golang.org/x/crypto@"$XC_VER")
  SRC=$(cd "$ROOT/outils/wg-tc" && GOOS= GOARCH= go list -m -f '{{.Dir}}' golang.org/x/crypto@"$XC_VER")
  cp -R "$SRC" "$T/x-crypto-tc"; chmod -R u+w "$T/x-crypto-tc"
  patch -d "$T/x-crypto-tc" -p1 < "$ROOT/analyse/x-crypto-poly1305-32bit.patch"
fi

# 4. Compilation
mkdir -p "$ROOT/binaires"
for p in wg-tc tc-swap relive tc-dhcp tc-pont; do
  log "compilation de $p"
  (cd "$ROOT/outils/$p" && go build -trimpath -ldflags="-s -w" -o "$ROOT/binaires/$p" .)
done
ls -la "$ROOT/binaires/wg-tc" "$ROOT/binaires/tc-swap" "$ROOT/binaires/relive" "$ROOT/binaires/tc-dhcp" "$ROOT/binaires/tc-pont"
