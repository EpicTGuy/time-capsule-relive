#!/usr/bin/env bash
#
# Envoie un fichier sur la Time Capsule sans risque de fichier tronqué : copie vers « .n », contrôle de la
# taille, puis renommage. (Un envoi interrompu a déjà laissé un tc-pont de 0 octet, relancé tel quel.)
#
#   outils/tc-envoyer.sh binaires/tc-pont /Volumes/dk2/.seconde-vie/bin/tc-pont
set -euo pipefail
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$1"; dst="$2"
taille=$(stat -f %z "$src")
"$RACINE/outils/tc-ssh.sh" "/bin/cat > '$dst.n'" < "$src"
recu=$("$RACINE/outils/tc-ssh.sh" "/bin/ls -l '$dst.n'" </dev/null | awk '{print $5}')
if [ "$recu" != "$taille" ]; then
  echo "envoi incomplet ($recu / $taille octets) : $dst inchangé" >&2
  "$RACINE/outils/tc-ssh.sh" "/bin/rm -f '$dst.n'" </dev/null
  exit 1
fi
"$RACINE/outils/tc-ssh.sh" "/bin/chmod 755 '$dst.n' && /bin/mv '$dst.n' '$dst'" </dev/null
echo "$dst : $taille octets"
