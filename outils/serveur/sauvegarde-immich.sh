#!/bin/bash
#
# Sauvegarde chiffrée des photos Immich de serveur-maison vers la Time Capsule.
#
#   /usr/local/sbin/sauvegarde-immich.sh            sauvegarde + rotation
#   /usr/local/sbin/sauvegarde-immich.sh verifier   contrôle de l'intégrité (5 % des données relues)
#   /usr/local/sbin/sauvegarde-immich.sh restic …   commande restic sur le dépôt (snapshots, restore…)
#
# restic chiffre tout sur serveur-maison (AES-256 + Poly1305) avant l'envoi : la Time Capsule
# ne stocke que des blocs illisibles sans le mot de passe du dépôt. Transport :
# backend SMB natif de rclone (remote « tcsmb »), sans montage.
#
# Sauvegardé : originaux (upload, library, profile) et dumps quotidiens de la base
# (backups, faits par Immich à 2 h). Exclus : encoded-video et thumbs, qu'Immich
# régénère.
#
# Mot de passe du dépôt : /root/.config/restic/immich.pass (600). Sans lui, la
# sauvegarde est perdue : en garder une copie hors de serveur-maison.

set -euo pipefail

export RESTIC_REPOSITORY="rclone:tcsmb:Data/immich-restic"
export RESTIC_PASSWORD_FILE="/root/.config/restic/immich.pass"
# Cache local de restic (index, arbres) : sans lui, chaque sauvegarde relit tout le dépôt.
export RESTIC_CACHE_DIR="/var/cache/restic"
SOURCE="/home/yunohost.app/immich"
# 2 connexions SMB au lieu de 5 : chaque connexion coûte un processus smbd
# (~7 Mo) sur la Time Capsule, dont la RAM est comptée.
restic() { command restic -o rclone.connections=2 "$@"; }
JOURNAL="/var/log/sauvegarde-immich.log"

log() { echo "$(date '+%F %T') $*" | tee -a "$JOURNAL"; }

case "${1:-sauvegarder}" in
  restic)
    shift
    restic "$@"
    ;;
  verifier)
    log "vérification : début"
    restic check --read-data-subset=5% 2>&1 | tee -a "$JOURNAL"
    log "vérification : fin"
    ;;
  sauvegarder)
    log "sauvegarde : début"
    restic backup "$SOURCE" \
      --exclude "$SOURCE/encoded-video" \
      --exclude "$SOURCE/thumbs" \
      --tag immich --host serveur-maison \
      --compression auto 2>&1 | tail -n 15 | tee -a "$JOURNAL"
    # 7 jours, 5 semaines, 12 mois, 3 ans
    restic forget --tag immich --keep-daily 7 --keep-weekly 5 --keep-monthly 12 --keep-yearly 3 \
      --prune 2>&1 | tail -n 5 | tee -a "$JOURNAL"
    log "sauvegarde : fin"
    ;;
  *)
    echo "usage : $0 [sauvegarder|verifier|restic …]" >&2
    exit 2
    ;;
esac
