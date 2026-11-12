#!/usr/bin/env bash
#
# Installe l'outillage de rétro-ingénierie dans .re-tools/ (hors dépôt), sans
# sudo ni modification du système :
#   - Node.js 24 LTS   (REA exige 22.23.4+, 24.22.1+ ou 26.12.1+)
#   - JDK 21 Temurin   (Ghidra 12.1 exige JDK 21+)
#   - Ghidra 12.1.4    (seule ligne acceptée par REA 6.8 ; vérifiée avec 12.1.4)
#   - décompilateur natif macOS arm64, absent de l'archive officielle
#   - REA (rea-agents), serveur MCP qui pilote Ghidra
#
#   ./outils/install-re-tools.sh
#
# Chaque archive est vérifiée par sa somme SHA-256 avant extraction.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$ROOT/.re-tools"
DL="$TOOLS/dl"

NODE_VER="v24.22.2"
GHIDRA_VER="12.1.4_PUBLIC_20260921"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_${GHIDRA_VER}.zip"
GHIDRA_SHA="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
REA_VER="6.8.0"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { echo "ECHEC : $*" >&2; exit 1; }

check_sha() { # fichier somme
  local got; got="$(shasum -a 256 "$1" | cut -d' ' -f1)"
  [ "$got" = "$2" ] || die "somme de $(basename "$1") : attendue $2, obtenue $got"
}

fetch() { # url fichier somme
  if [ ! -f "$2" ] || [ "$(shasum -a 256 "$2" | cut -d' ' -f1)" != "$3" ]; then
    log "téléchargement de $(basename "$2")"
    curl -fsSL --max-time 1800 -o "$2" "$1"
  fi
  check_sha "$2" "$3"
}

[ "$(uname -s)/$(uname -m)" = "Darwin/arm64" ] || die "script prévu pour macOS Apple Silicon"
mkdir -p "$DL"

# --- Node.js ------------------------------------------------------------------
if [ -x "$TOOLS/node/bin/node" ]; then
  log "Node déjà installé"
else
  name="node-${NODE_VER}-darwin-arm64.tar.gz"
  sha="$(curl -fsSL "https://nodejs.org/dist/${NODE_VER}/SHASUMS256.txt" | awk -v n="$name" '$2==n {print $1}')"
  [ -n "$sha" ] || die "somme de $name introuvable"
  fetch "https://nodejs.org/dist/${NODE_VER}/${name}" "$DL/$name" "$sha"
  log "extraction de Node"
  rm -rf "$TOOLS/node" "$TOOLS/node-tmp"; mkdir -p "$TOOLS/node-tmp"
  tar -xzf "$DL/$name" -C "$TOOLS/node-tmp"
  mv "$TOOLS/node-tmp/node-${NODE_VER}-darwin-arm64" "$TOOLS/node"; rm -rf "$TOOLS/node-tmp"
fi
"$TOOLS/node/bin/node" -v | sed 's/^/    node /'

# --- JDK 21 -------------------------------------------------------------------
if [ -x "$TOOLS/jdk/bin/java" ]; then
  log "JDK déjà installé"
else
  api="https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=aarch64&image_type=jdk&os=mac&vendor=eclipse"
  read -r url sha < <(curl -fsSL "$api" | python3 -c '
import json, sys
p = json.load(sys.stdin)[0]["binary"]["package"]
print(p["link"], p["checksum"])')
  fetch "$url" "$DL/jdk21.tar.gz" "$sha"
  log "extraction du JDK"
  rm -rf "$TOOLS/jdk" "$TOOLS/jdk-tmp"; mkdir -p "$TOOLS/jdk-tmp"
  tar -xzf "$DL/jdk21.tar.gz" -C "$TOOLS/jdk-tmp"
  home="$(find "$TOOLS/jdk-tmp" -maxdepth 3 -type d -name Home | head -1)"
  [ -n "$home" ] || die "Contents/Home introuvable dans l'archive JDK"
  mv "$home" "$TOOLS/jdk"; rm -rf "$TOOLS/jdk-tmp"
fi
"$TOOLS/jdk/bin/java" -version 2>&1 | head -1 | sed 's/^/    /'

# --- Ghidra -------------------------------------------------------------------
if [ -x "$TOOLS/ghidra/support/analyzeHeadless" ]; then
  log "Ghidra déjà installé"
else
  fetch "$GHIDRA_URL" "$DL/ghidra_${GHIDRA_VER}.zip" "$GHIDRA_SHA"
  log "extraction de Ghidra"
  rm -rf "$TOOLS/ghidra" "$TOOLS/ghidra-tmp"; mkdir -p "$TOOLS/ghidra-tmp"
  unzip -q "$DL/ghidra_${GHIDRA_VER}.zip" -d "$TOOLS/ghidra-tmp"
  mv "$TOOLS/ghidra-tmp"/ghidra_* "$TOOLS/ghidra"; rm -rf "$TOOLS/ghidra-tmp"
fi

# --- Décompilateur natif macOS arm64 -----------------------------------------
# L'archive ne livre que linux_x86_64 et win_x86_64. On compile la cible
# ghidra_opt (le binaire « decompile » que Ghidra lance) et sleigh_opt. Les
# sources qui dépendent de libbfd ne servent qu'à la console de test : retirées.
DECOMP="$TOOLS/ghidra/Ghidra/Features/Decompiler"
if [ -x "$DECOMP/os/mac_arm_64/decompile" ]; then
  log "décompilateur arm64 déjà présent"
else
  log "compilation du décompilateur arm64"
  build="$TOOLS/decomp-build"
  rm -rf "$build"; mkdir -p "$build"
  cp -R "$DECOMP/src/decompile" "$build/"
  (
    cd "$build/decompile/cpp"
    for f in $(grep -l -E '#include.*(bfd|loadimage_bfd|bfd_arch)' ./*.cc); do rm "$f"; done
    mkdir -p com_opt sla_opt ghi_opt
    make -j"$(sysctl -n hw.ncpu)" ARCH_TYPE="-arch arm64" ghidra_opt sleigh_opt > "$build/build.log" 2>&1 \
      || die "compilation, voir $build/build.log"
  )
  mkdir -p "$DECOMP/os/mac_arm_64"
  cp "$build/decompile/cpp/ghidra_opt" "$DECOMP/os/mac_arm_64/decompile"
  cp "$build/decompile/cpp/sleigh_opt" "$DECOMP/os/mac_arm_64/sleigh"
  rm -rf "$build"
fi
file "$DECOMP/os/mac_arm_64/decompile" | sed 's/^/    /'

# --- REA ------------------------------------------------------------------------
export PATH="$TOOLS/node/bin:$PATH"
if [ -x "$TOOLS/rea/node_modules/.bin/rea" ] && \
   [ "$("$TOOLS/node/bin/node" -p "require('$TOOLS/rea/node_modules/rea-agents/package.json').version")" = "$REA_VER" ]; then
  log "REA $REA_VER déjà installé"
else
  log "installation de REA $REA_VER"
  rm -rf "$TOOLS/rea"; mkdir -p "$TOOLS/rea"
  (cd "$TOOLS/rea" && npm init -y >/dev/null && npm install --no-fund --no-audit "rea-agents@$REA_VER" >/dev/null)
fi

log "terminé — vérifier avec : source outils/re-env.sh && rea doctor"
