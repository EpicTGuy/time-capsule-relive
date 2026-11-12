#!/usr/bin/env bash
#
# SSH vers la Time Capsule (root), mot de passe tiré du trousseau macOS par
# SSH_ASKPASS (outils/motdepasse.py) : rien n'est écrit sur disque.
#
#   outils/tc-ssh.sh                  # shell
#   outils/tc-ssh.sh 'uname -a'       # commande
#
# Algorithmes anciens requis par l'OpenSSH de NetBSD 6 (mêmes options que TimeCapsuleSMB).
set -euo pipefail
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOTE="${TC_HOTE:-$(sed -n 's/^TC_HOTE=//p' "$RACINE/config.local" 2>/dev/null)}"
[ -n "$HOTE" ] || { echo "définir TC_HOTE (ou config.local)" >&2; exit 2; }

if [ "${1:-}" = "--askpass" ]; then
  exec "$RACINE/.re-tools/venv/bin/python" -c \
    "import sys; sys.path.insert(0, '$RACINE/outils'); import motdepasse; print(motdepasse.obtenir())"
fi

export SSH_ASKPASS="$RACINE/outils/tc-ssh.sh" SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-:0}"
# SSH_ASKPASS est appelé sans argument : petit relais qui ajoute --askpass
RELAIS="$(mktemp -t tc-askpass)"; trap 'rm -f "$RELAIS"' EXIT
printf '#!/bin/sh\nexec "%s" --askpass\n' "$RACINE/outils/tc-ssh.sh" > "$RELAIS"; chmod 700 "$RELAIS"
export SSH_ASKPASS="$RELAIS"

ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o KexAlgorithms=+diffie-hellman-group14-sha1 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PreferredAuthentications=password,keyboard-interactive \
    "root@$HOTE" "$@"
