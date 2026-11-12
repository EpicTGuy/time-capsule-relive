#!/bin/sh
# Essai du répéteur DWDS avec un routeur non Apple, lancé par SSH câble branché :
#   nohup /bin/sh essai-dwds.sh >/var/log/essai-dwds.txt 2>&1 &
# 1. attend que le câble Ethernet soit débranché (10 min max ; le routeur OpenWrt ne répond plus au ping) ;
# 2. remplace le wpa_supplicant d'ACPd par la copie sans verrou (outils/wpa-sans-verrou.py),
#    lancée depuis un tmpfs (jamais depuis le disque HFS+) ;
# 3. une fois associée, met la radio client dans le pont (comme ACPd avec un routeur Apple) ;
# 4. garde-fou : si le câble revient, arrêt immédiat et radio retirée du pont (pas de boucle) ;
#    sinon arrêt au bout de 30 min.
D=/Volumes/dk2/.seconde-vie
T=/mnt/essai-wpa
I=wlan1
# bcmeth0/bcmeth1 restent « status: active » câble débranché (lien interne vers le commutateur) :
# avant la mise en pont, câble = le routeur OpenWrt répond au ping (seul chemin possible) ;
# après, câble = une adresse est réapprise sur bcmeth0 dans les 3 s qui suivent un vidage du pont.
ROUTEUR=192.168.1.1
routeur_repond() { /sbin/ping -c 1 -w 1 $ROUTEUR >/dev/null 2>&1; }
cable() {
  if dans_pont; then
    /sbin/brconfig bridge0 flush; /bin/sleep 3
    case "$(/sbin/brconfig bridge0)" in *" bcmeth0 "[0-9]*" flags="*) return 0;; esac; return 1
  fi
  routeur_repond || routeur_repond || routeur_repond
}
associee() { case "$(/sbin/ifconfig $I 2>/dev/null)" in *"status: associated"*) return 0;; esac; return 1; }
dans_pont() { case "$(/sbin/brconfig bridge0)" in *"$I flags"*) return 0;; esac; return 1; }
log() { echo "$(/bin/date '+%T') $*"; }

/bin/mkdir -p $T; /sbin/mount_tmpfs -s 12m tmpfs $T 2>/dev/null
/bin/cp $D/bin/wpa_supplicant-dwds $T/wpa_supplicant || exit 1
log "prêt, attente du débranchement du câble"
n=0; while cable; do n=$((n+1)); [ $n -gt 600 ] && { log "câble jamais débranché, abandon"; exit 1; }; /bin/sleep 1; done
log "câble débranché"
for p in $(/bin/ps -axo pid,command | /usr/bin/sed -n 's/^ *\([0-9]*\) \/sbin\/wpa_supplicant.*/\1/p'); do /bin/kill $p; done
$T/wpa_supplicant -K -M -F /var/log/hostap_${I}-dwds.log -D net80211 -i $I -c /etc/hostap_${I}.conf &
P=$!
log "supplicant corrigé lancé (pid $P)"
n=0; etat=""
while [ $n -lt 1800 ]; do
  if cable; then
    /bin/kill $P; dans_pont && /sbin/brconfig bridge0 delete $I
    log "câble rebranché : supplicant arrêté, radio retirée du pont"; exit 0
  fi
  if associee; then
    [ "$etat" != a ] && { log "associée"; etat=a; }
    dans_pont || { /sbin/brconfig bridge0 add $I && log "radio ajoutée au pont"; }
  else
    [ "$etat" != n ] && { log "non associée"; etat=n; }
  fi
  n=$((n+1)); /bin/sleep 1
done
/bin/kill $P; dans_pont && /sbin/brconfig bridge0 delete $I; log "fin des 30 min"
