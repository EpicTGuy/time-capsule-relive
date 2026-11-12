#!/bin/sh
# Script principal « seconde vie », sur le disque : /Volumes/dk2/.seconde-vie/demarrage.sh
#   - mémoire d'échange (swap) sur le disque ;
#   - arrêt des démons Apple devenus inutiles (AFP remplacé par SMB 3, iCloud fermé en 2019) ;
#   - relevé SMART du disque toutes les 30 min (partage Data : .seconde-vie/smart.txt) ;
#   - WireGuard en espace utilisateur (wg-tc), relancé s'il s'arrête (si wg/wg0.conf existe) ;
#   - interface web ReLive en HTTPS (https://adresse-de-la-time-capsule, le port 80 y redirige), relancée si elle s'arrête.
# Journal : /mnt/Memory/seconde-vie.log (en RAM, effacé au redémarrage).
PATH=/bin:/sbin:/usr/bin:/usr/sbin
D=/Volumes/dk2/.seconde-vie
PARTAGE=/Volumes/dk2/ShareRoot/.seconde-vie   # visible par SMB (partage Data) : état seulement
exec >>/mnt/Memory/seconde-vie.log 2>&1
echo "$(date '+%F %T') démarrage"

# 0. Les programmes s'exécutent depuis la RAM (tmpfs), jamais depuis le disque :
#    le pilote HFS+ du noyau rend des pages fausses quand il projette un gros
#    exécutable en mémoire (code remplacé par des zéros, écritures « perdues »).
#    La lecture ordinaire est fiable : on copie, puis on lance la copie.
#    (Même raison pour laquelle TimeCapsuleSMB copie smbd en RAM.)
BIN=/mnt/seconde-vie
mkdir -p "$BIN"
case "$(mount)" in *" on $BIN "*) ;; *) mount_tmpfs -s 40m tmpfs "$BIN" ;; esac
for prog in tc-swap relive wg-tc tc-dhcp tc-pont; do
    if [ -f "$D/bin/$prog" ]; then
        cp "$D/bin/$prog" "$BIN/.$prog" && chmod 755 "$BIN/.$prog" && mv -f "$BIN/.$prog" "$BIN/$prog"
    fi
done

# 1. Swap (à couper avant toute réparation ou effacement du disque : tc-swap off)
if [ -f "$D/swap0" ]; then "$BIN/tc-swap" on "$D/swap0"; fi

# 2. Démons inutiles : remplacés en RAM par un garde qui s'arrête aussitôt
#    (même technique que le boot.sh de TimeCapsuleSMB), puis arrêtés.
for demon in afpserver iCloudd; do
    if [ -f "/sbin/$demon" ] && [ ! -L "/sbin/$demon" ]; then
        printf '#!/bin/sh\nexit 0\n' >"/sbin/.$demon.$$" && chmod 555 "/sbin/.$demon.$$" &&
            mv -f "/sbin/.$demon.$$" "/sbin/$demon"
    fi
    pkill -x "$demon" 2>/dev/null && echo "$demon arrêté"
done

# 3. Santé du disque : relevé SMART toutes les 30 min, lu par la sonde du serveur (SMB)
(
    while :; do
        mkdir -p "$PARTAGE" && atactl wd0 smart status >"$PARTAGE/smart.txt.tmp" 2>&1 &&
            mv -f "$PARTAGE/smart.txt.tmp" "$PARTAGE/smart.txt"
        sleep 1800
    done
) &

# 4. WireGuard : relancé en cas d'arrêt (pause croissante, 5 min au plus)
if [ -f "$D/wg/wg0.conf" ]; then
    (
        pause=5
        while :; do
            "$BIN/wg-tc" -c "$D/wg/wg0.conf"
            echo "$(date '+%F %T') wg-tc arrêté (code $?), relance dans ${pause}s"
            sleep "$pause"
            [ "$pause" -lt 300 ] && pause=$((pause * 2))
        done
    ) &
fi
# 5. Interface web ReLive (HTTPS 443, HTTP 80 redirigé), relancée si elle s'arrête
if [ -x "$BIN/relive" ]; then
    (
        while :; do
            "$BIN/relive" -ecoute :80 -dossier "$D" >>"$D/relive.log" 2>&1
            echo "$(date '+%F %T') relive arrêté (code $?), relance dans 10 s"
            sleep 10
        done
    ) &
fi
# 6. Radio en client Wi-Fi simple (box ou routeur quelconque) : la Time Capsule devient joignable par ce
#    Wi-Fi grâce à tc-pont (relais.sh joindre) ; surveillé, relancé si l'association revient. Sans câble
#    Ethernet, elle partage aussi cette connexion sur son propre Wi-Fi (relais.sh garde, coupé dès que le
#    câble revient).
if [ -x "$BIN/tc-pont" ] && [ -f "$D/relais.sh" ]; then
    (
        while :; do
            # une radio associée en client simple (pas le répéteur Apple, que ACPd met lui-même dans le pont)
            if ! /bin/sh "$D/relais.sh" client; then
                /bin/sh "$D/relais.sh" cable # état du câble pour le mode automatique de ReLive
            else
                kill -0 "$(cat /tmp/relais/pont.pid 2>/dev/null)" 2>/dev/null || /bin/sh "$D/relais.sh" joindre
                kill -0 "$(cat /tmp/relais/garde.pid 2>/dev/null)" 2>/dev/null || {
                    /bin/sh "$D/relais.sh" garde >>/tmp/relais/garde.log 2>&1 &
                    echo $! >/tmp/relais/garde.pid
                }
            fi
            # journaux du relais en RAM (/tmp, 15 Mo pour tout le système) : plafonnés à 200 Ko
            for j in /tmp/relais/*.log; do
                [ -f "$j" ] && [ "$(ls -l "$j" | sed 's/^[^ ]* *[^ ]* *[^ ]* *[^ ]* *\([0-9]*\).*/\1/')" -gt 204800 ] &&
                    { tail -200 "$j" >"$j.n" && mv -f "$j.n" "$j"; }
            done
            sleep 30
        done
    ) &
fi
echo "$(date '+%F %T') prêt"
