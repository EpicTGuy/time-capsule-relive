#!/usr/bin/env bash
#
# Environnement de rétro-ingénierie installé par outils/install-re-tools.sh
# dans .re-tools/ : Node 24, JDK 21, Ghidra 12.1.4 (+ décompilateur arm64), REA.
#
#   source outils/re-env.sh          # exporte GHIDRA_INSTALL_DIR, JAVA_HOME, PATH
#   outils/re-env.sh rea doctor      # lance une commande dans cet environnement
#   outils/re-env.sh analyzeHeadless <args...>

RE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RE_TOOLS="$RE_ROOT/.re-tools"

export GHIDRA_INSTALL_DIR="$RE_TOOLS/ghidra"
export JAVA_HOME="$RE_TOOLS/jdk"
export PATH="$RE_TOOLS/rea/node_modules/.bin:$RE_TOOLS/node/bin:$JAVA_HOME/bin:$PATH"

if [ ! -x "$JAVA_HOME/bin/java" ] || [ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then
  echo "Outils absents — lancer ./outils/install-re-tools.sh" >&2
  return 1 2>/dev/null || exit 1
fi

# Exécuté (pas sourcé) avec des arguments : lance la commande demandée.
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ $# -gt 0 ]; then
  if [ -x "$GHIDRA_INSTALL_DIR/support/$1" ]; then
    tool="$1"; shift
    exec "$GHIDRA_INSTALL_DIR/support/$tool" "$@"
  fi
  exec "$@"
fi
