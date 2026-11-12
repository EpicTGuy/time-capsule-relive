#!/bin/sh
# Lanceur « Time Capsule — seconde vie », appelé par /mnt/Flash/rc.local.
# Attend le disque (monté par TimeCapsuleSMB) puis lance le script principal.
# Rien à faire si le disque ou le script manque : la Time Capsule démarre normalement.
PATH=/bin:/sbin:/usr/bin:/usr/sbin
S=/Volumes/dk2/.seconde-vie/demarrage.sh
i=0
while [ ! -x "$S" ] && [ "$i" -lt 60 ]; do sleep 5; i=$((i + 1)); done
[ -x "$S" ] && exec "$S"
exit 0
