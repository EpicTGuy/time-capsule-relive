#!/bin/sh
# Mode client et relais (« routeur de voyage ») : une radio de la Time Capsule rejoint un Wi-Fi quelconque (box,
# routeur, partage de connexion d'un téléphone) en simple client ; la Time Capsule devient joignable par ce
# Wi-Fi et, si le câble Ethernet ne mène pas à un réseau, partage la connexion sur son propre Wi-Fi (l'autre
# radio) et sur le câble (un routeur branché par son port WAN y prend son accès à Internet). Marche avec tout
# point d'accès WPA2, contrairement au répéteur Apple (DWDS) que seuls les routeurs Apple acceptent.
#
# Le noyau d'Apple refuse toute adresse IPv4 sur une radio cliente : tc-pont porte l'adresse (pile gVisor par
# BPF, MAC de la radio) et traduit les adresses des appareils partagés (NAT, docs/spec-nat.md). pf n'est pas
# utilisable : le pf d'Apple corrompt la somme de contrôle des paquets qu'il retraduit.
# Notes : docs/analyse-firmware-7.9.1.md.
#
# Préalable : une radio en client simple (ReLive → Wi-Fi → « Rejoindre un réseau Wi-Fi »). Radio 0 → wlan0
# (5 GHz), radio 1 → wlan1 (2,4 GHz) ; la cliente est celle qui est « associated ».
#
#   relais.sh joindre    adresse sur le Wi-Fi client (tc-dhcp), portée par tc-pont
#   relais.sh relais     + partage : réseau 10.42.42.0/24 sur l'autre radio et le câble (noyau en .1 : DHCP,
#                        services ; tc-pont : relais DNS en .1 et traduction du reste vers le Wi-Fi client) ;
#                        refusé si le câble mène à un réseau (DHCP en double sinon)
#   relais.sh garde      relais, puis surveillance : câble vers un réseau → partage coupé aussitôt
#   relais.sh couper     arrête le partage seul
#   relais.sh arreter    défait tout (comme un redémarrage)
#   relais.sh etat
#   relais.sh client     vrai si une radio est associée en client simple
#   relais.sh cable      vrai si le câble Ethernet mène à un réseau (état noté dans $R/cable)
#
# Rien n'est écrit dans la flash ni dans /etc : tout est dans $R (disque RAM) et disparaît au redémarrage.
PATH=/bin:/sbin:/usr/bin:/usr/sbin
LAN=bridge0
R=/tmp/relais
D=/Volumes/dk2/.seconde-vie
BIN=/mnt/seconde-vie   # programmes copiés en RAM (jamais lancés depuis le disque HFS+)
RESEAU=10.42.42
mkdir -p $R
log() { echo "$(date '+%F %T') $*"; }
# Déconnecte les appareils du Wi-Fi de la Time Capsule : ils se reconnectent aussitôt et redemandent une adresse
# (sinon ils gardent des heures celle du réseau d'avant — 192.168.1.x par le câble, 10.42.42.x par le relais).
reconnecter() {
    for a in $(cat $R/ap); do
        for m in $(wl -i $a assoclist 2>/dev/null | sed -n 's/^assoclist //p'); do wl -i $a deauthenticate $m 2>/dev/null; done
    done
}
ether() { ifconfig "$1" 2>/dev/null | sed -n 's/^.ether //p'; }

# Radio cliente (associée, hors répéteur Apple) et Wi-Fi de la Time Capsule (interface wlan membre de bridge0 :
# wlan0 si la cliente est la 2,4 GHz, wlan2 si c'est la 5 GHz ; plus le réseau invité, sur la radio cliente,
# s'il est activé : répétition sur la même bande), notées dans $R/client et $R/ap (une par ligne).
interfaces() {
    for i in wlan0 wlan1; do
        case "$(cat /etc/hostap_$i.conf 2>/dev/null)" in *dwds_role=3*) continue ;; esac
        case "$(ifconfig $i 2>/dev/null)" in *"status: associated"*)
            echo $i >$R/client
            brconfig $LAN | sed -n "s/^[[:space:]]*\(wlan[0-9]\) flags=.*/\1/p" | sed "/^$i\$/d" >$R/ap
            return 0 ;;
        esac
    done
    return 1
}

# Client 5 GHz : ACPd donne à bridge0 la MAC de la radio cliente ; câble branché, le noyau a déjà par le câble
# la même adresse que tc-pont aurait sur le Wi-Fi. tc-pont ne doit alors pas tourner (même MAC, même adresse
# sur deux chemins : le routeur la verrait sauter de l'un à l'autre).
meme_identite() { [ "$(ether $LAN)" = "$(ether "$(cat $R/client)")" ]; }

# Câble branché = une adresse est réapprise sur bcmeth0 dans les 3 s qui suivent un vidage du pont (bcmeth0 et
# bcmeth1 restent « status: active » câble débranché : lien interne vers le commutateur). Il mène alors à un
# réseau (box, routeur par un port LAN : un serveur DHCP répond à la sonde de tc-dhcp) ou à un appareil qui
# attend une adresse (routeur branché par son port WAN). Sonde au plus une fois par minute ; deux sans réponse
# avant de conclure « pas de réseau » (servir des adresses sur le réseau de la maison le perturberait), et dans
# le doute (sonde impossible), réseau.
# $R/cable : 0 = rien, 1 = réseau, 2 = appareil en attente. Lu par tc-pont (relais Bonjour en pause sur 1) et
# par le mode automatique de ReLive.
cable() {
    brconfig $LAN flush; sleep 3
    case "$(brconfig $LAN)" in *" bcmeth0 "[0-9]*" flags="*) ;; *)
        rm -f $R/sonde; echo 0 >$R/cable; return 1 ;;
    esac
    etat=$(cat $R/cable 2>/dev/null); s=$(cat $R/sonde 2>/dev/null) # « heure échecs »
    t=${s%% *}; echecs=${s##* }; maintenant=$(date +%s)
    if [ "$etat" != 1 ] && [ "$etat" != 2 ] || [ "${echecs:-0}" = 1 ] || [ $((maintenant - ${t:-0})) -ge 60 ]; then
        # Sur un membre du pont, le noyau envoie la sonde par tout le pont (bridge_output), Wi-Fi client compris :
        # seule compte une réponse dont la MAC est apprise sur bcmeth0.
        r=$($BIN/tc-dhcp -i bcmeth0 -mac "$(ether $LAN)" -sonde -ignorer $RESEAU.1 2>/dev/null); code=$?
        if [ $code = 0 ]; then case "$(brconfig $LAN)" in *"${r##* } bcmeth0 "*) ;; *) code=3 ;; esac; fi
        case $code in
        0) echecs=0; etat=1 ;;
        3) echecs=$((${echecs:-0} + 1)); [ $echecs -ge 2 ] && etat=2 ;;
        *) echecs=0 ;;
        esac
        [ "$etat" = 1 ] || [ "$etat" = 2 ] || etat=1
        [ "$etat" = "$(cat $R/cable 2>/dev/null)" ] || log "câble : $([ $etat = 1 ] && echo "réseau" || echo "appareil sans réseau (routeur en WAN ?)")"
        echo "$maintenant $echecs" >$R/sonde; echo $etat >$R/cable
    fi
    [ "$etat" = 1 ]
}

# Scripts du client DHCP (tc-dhcp) et de lancement de tc-pont, écrits dans $R.
ecrire_scripts() {
    cat >$R/dhclient-script <<'FIN'
#!/bin/sh
R=/tmp/relais
case "$reason" in
BOUND|RENEW|REBIND|REBOOT)
    echo "$new_ip_address" >$R/ip; echo "$new_subnet_mask" >$R/masque
    echo "${new_routers%% *}" >$R/passerelle; echo "$new_domain_name_servers" >$R/dns
    voulu="$new_ip_address $new_subnet_mask ${new_routers%% *}"
    [ "$(cat $R/pont.bail 2>/dev/null)" = "$voulu" ] && kill -0 "$(cat $R/pont.pid 2>/dev/null)" 2>/dev/null ||
        /bin/sh $R/lancer-pont.sh ;;
EXPIRE|FAIL|RELEASE|STOP)
    [ -f $R/pont.pid ] && kill "$(cat $R/pont.pid)" 2>/dev/null
    [ -s $R/ancienne-ip ] && route -q delete -host "$(cat $R/ancienne-ip)"
    rm -f $R/ip $R/pont.pid $R/pont.bail $R/ancienne-ip ;;
esac
exit 0
FIN
    cat >$R/lancer-pont.sh <<'FIN'
#!/bin/sh
# (Re)lance tc-pont avec le bail courant ; traduction d'adresses pour les appareils si le partage est actif.
PATH=/bin:/sbin:/usr/bin:/usr/sbin
R=/tmp/relais
[ -s $R/ip ] && [ -s $R/client ] || exit 1
[ -f $R/pont.pid ] && kill "$(cat $R/pont.pid)" 2>/dev/null
ip=$(cat $R/ip); gw=$(cat $R/passerelle); masque=$(cat $R/masque 2>/dev/null || echo 255.255.255.0)
client=$(cat $R/client)
# Les deux radios (et leurs interfaces) partagent une MAC : un paquet pour l'adresse Wi-Fi arrivé par le câble
# serait réacheminé par le noyau (ip.forwarding=1) et ferait 64 tours routeur OpenWrt ↔ Time Capsule. Route « trou
# noir » : le noyau l'abandonne, seule la pile de tc-pont répond.
# Client 5 GHz : bridge0 porte la MAC de la cliente et le noyau peut garder, d'un bail pris par le câble, la
# même adresse : il répondrait alors lui aussi aux paquets arrivés par le Wi-Fi (connexions remises à zéro une
# fois sur deux). On la lui retire (rendue quand le câble revient, voir joindre).
case "$(ifconfig bridge0)" in *"inet $ip "*)
    ifconfig bridge0 | sed -n "s/^.inet $ip netmask \([^ ]*\).*/\1/p" >$R/ip-noyau.masque
    echo "$ip" >$R/ip-noyau; ifconfig bridge0 inet "$ip" delete ;;
esac
[ -s $R/ancienne-ip ] && route -q delete -host "$(cat $R/ancienne-ip)"
route -q add -host "$ip" 127.0.0.1 -blackhole; echo "$ip" >$R/ancienne-ip
dns=$(cat $R/dns 2>/dev/null); dns=${dns%% *}; [ -n "$dns" ] || dns=$gw
options=""
[ -s $R/relais ] &&
    options="-lan $(echo $(cat $R/ap) | sed 's/ /,/g') -lan-cable bcmeth0 -lan-mac $(ifconfig bridge0 | sed -n 's/^.ether //p') -dns-amont $dns"
# Réseau de confiance (liste tenue par ReLive) : sinon, ni SSH, ni ReLive, ni partage, ni Bonjour vers ce réseau.
ssid=$(wl -i $client ssid 2>/dev/null | sed -n 's/^Current SSID: "\(.*\)"$/\1/p')
confiance=0
if [ -f /Volumes/dk2/.seconde-vie/reseaux-confiance.txt ]; then
    while IFS= read -r l; do [ -n "$ssid" ] && [ "$l" = "$ssid" ] && confiance=1; done </Volumes/dk2/.seconde-vie/reseaux-confiance.txt
fi
[ $confiance = 1 ] || options="$options -ports= -mdns=false"
mac=$(ifconfig $client 2>/dev/null | sed -n 's/^.ether //p')
nohup /mnt/seconde-vie/tc-pont -i $client -mac "$mac" -ip "$ip" -masque "$masque" -passerelle "$gw" $options \
    >>$R/tc-pont.log 2>&1 </dev/null &
echo $! >$R/pont.pid
echo "$ip $masque $gw" >$R/pont.bail
FIN
    chmod 755 $R/dhclient-script $R/lancer-pont.sh   # tc-dhcp exécute le script directement
}

joindre() {
    interfaces || { log "aucune radio cliente associée : rien à faire"; return 1; }
    I=$(cat $R/client)
    ecrire_scripts
    # En client simple, ACPd met aussi la radio cliente dans bridge0 : le câble et ce Wi-Fi seraient pontés.
    case "$(brconfig $LAN)" in *"$I flags"*) brconfig $LAN delete $I && log "$I retirée de $LAN" ;; esac
    if meme_identite && cable; then
        [ -f $R/par-cable ] || log "client $I et câble branché : la Time Capsule répond par le câble, tc-pont s'efface"
        : >$R/par-cable; arreter >/dev/null
        if [ -s $R/ip-noyau ]; then # adresse du câble mise de côté par lancer-pont.sh : la rendre au noyau
            ifconfig $LAN inet "$(cat $R/ip-noyau)" netmask "$(cat $R/ip-noyau.masque)" alias
            rm -f $R/ip-noyau $R/ip-noyau.masque
        fi
        return 0
    fi
    rm -f $R/par-cable
    if kill -0 "$(cat $R/dhclient.pid 2>/dev/null)" 2>/dev/null; then
        kill -0 "$(cat $R/pont.pid 2>/dev/null)" 2>/dev/null && { log "déjà joint : $(cat $R/ip 2>/dev/null)"; return 0; }
        log "tc-pont arrêté : nouveau départ (client DHCP compris)"
        kill "$(cat $R/dhclient.pid)"; rm -f $R/dhclient.pid $R/pont.pid $R/pont.bail $R/ip
    fi
    # copie en RAM à jour (date, pas taille : deux versions compilées ont souvent la même taille) ;
    # un fichier vide (envoi interrompu) n'est jamais recopié
    for prog in tc-dhcp tc-pont; do
        if [ -s "$D/bin/$prog" ] && [ "$D/bin/$prog" -nt "$BIN/$prog" ]; then
            cp "$D/bin/$prog" "$BIN/.$prog" && chmod 755 "$BIN/.$prog" && mv -f "$BIN/.$prog" "$BIN/$prog"
        fi
    done
    # le dhclient d'Apple s'arrête sans rien dire sur une radio cliente : tc-dhcp (BPF) à la place
    nohup $BIN/tc-dhcp -i $I -mac "$(ether $I)" -nom "$(hostname)" -script $R/dhclient-script >>$R/tc-dhcp.log 2>&1 &
    echo $! >$R/dhclient.pid
    i=0; while [ ! -s $R/ip ] && [ $i -lt 40 ]; do sleep 1; i=$((i + 1)); done
    [ -s $R/ip ] || { log "pas d'adresse DHCP sur $I"; return 1; }
    log "joignable par le Wi-Fi ($I) en $(cat $R/ip), passerelle $(cat $R/passerelle)"
}

relais() {
    if cable; then
        # relancé toutes les 30 s par demarrage.sh : ne le noter qu'une fois (journal en RAM, 15 Mo en tout)
        [ -f $R/refus ] || log "câble Ethernet vers un réseau : partage refusé (le DHCP du relais le gênerait)"
        : >$R/refus; return 1
    fi
    rm -f $R/refus
    joindre || return 1
    [ -s $R/relais ] && return 0
    # .1 au noyau (passerelle des appareils, DHCP, services de la Time Capsule). Son routage est coupé : il
    # ignore les paquets vers l'extérieur, que tc-pont lit et traduit.
    ifconfig $LAN inet $RESEAU.1 netmask 255.255.255.0 alias
    sysctl -n net.inet.ip.forwarding >$R/forwarding
    sysctl -w net.inet.ip.forwarding=0 >/dev/null
    cat >$R/dhcpd.conf <<FIN
authoritative;
default-lease-time 3600;
max-lease-time 86400;
subnet $RESEAU.0 netmask 255.255.255.0 {
  range $RESEAU.100 $RESEAU.199;
  option routers $RESEAU.1;
  option domain-name-servers $RESEAU.1;   # relais DNS de tc-pont, vers celui de la box
  server-identifier $RESEAU.1;   # sinon dhcpd se présente sous l'adresse du câble
}
# la Time Capsule elle-même (dhclient d'ACPd sur bridge0) ne prend pas d'adresse à son propre relais
host moi { hardware ethernet $(ether $LAN); ignore booting; }
FIN
    : >>$R/dhcpd.leases
    dhcpd -q -cf $R/dhcpd.conf -lf $R/dhcpd.leases -pf $R/dhcpd.pid $LAN
    echo $RESEAU.1 >$R/relais
    /bin/sh $R/lancer-pont.sh
    reconnecter
    log "partage actif : $RESEAU.0/24 sur $(echo $(cat $R/ap)) et le câble, sortie par $(cat $R/client) ($(cat $R/ip))"
}

couper() {
    [ -s $R/relais ] || return 0
    [ -f $R/dhcpd.pid ] && kill "$(cat $R/dhcpd.pid)" 2>/dev/null
    ifconfig $LAN inet $RESEAU.1 delete 2>/dev/null
    [ -s $R/forwarding ] && sysctl -w net.inet.ip.forwarding="$(cat $R/forwarding)" >/dev/null
    rm -f $R/relais $R/dhcpd.pid $R/forwarding
    [ -s $R/ip ] && /bin/sh $R/lancer-pont.sh
    reconnecter
    log "partage arrêté"
}

arreter() {
    couper
    for f in dhclient pont; do [ -f $R/$f.pid ] && kill "$(cat $R/$f.pid)" 2>/dev/null; done
    [ -s $R/ancienne-ip ] && route -q delete -host "$(cat $R/ancienne-ip)"
    rm -f $R/ancienne-ip $R/dhclient.pid $R/pont.pid $R/pont.bail $R/ip
    log "relais arrêté"
}

garde() {
    relais || exit 1
    while :; do
        if cable; then couper; log "câble vers un réseau : partage coupé"; exit 0; fi
        # Sans réponse DHCP, le dhclient d'ACPd pose 0.0.0.0 en tête de bridge0 : le noyau la prend alors comme
        # source du multicast (questions Bonjour relayées ignorées par mDNSResponder). On la retire.
        case "$(ifconfig $LAN)" in *"inet 0.0.0.0 "*) ifconfig $LAN inet 0.0.0.0 delete 2>/dev/null ;; esac
        # Sans câble, le dhclient d'ACPd finit par retirer toutes les adresses de bridge0, 10.42.42.1 comprise :
        # les appareils perdent leur passerelle (vu le 12/11/2026 : l'iPhone passait alors par le réseau mobile).
        case "$(ifconfig $LAN)" in *"inet $RESEAU.1 "*) ;; *)
            ifconfig $LAN inet $RESEAU.1 netmask 255.255.255.0 alias && log "10.42.42.1 remise sur $LAN" ;;
        esac
        sleep 5
    done
}

etat() {
    interfaces && echo "client $(cat $R/client) : IP $(cat $R/ip 2>/dev/null || echo aucune) ; Wi-Fi de la Time Capsule $(echo $(cat $R/ap))" ||
        echo "aucune radio cliente"
    [ -s $R/relais ] && echo "partage actif ($RESEAU.0/24) ; baux : $(sed -n 's/^lease \(.*\) {/\1/p' $R/dhcpd.leases)"
}

case "$1" in
client) interfaces ;; # code de retour seul : une radio est-elle cliente ? (surveillance de demarrage.sh)
cable) cable ;;       # état du câble noté dans $R/cable (tc-pont, mode automatique) ; 0 s'il mène à un réseau
joindre | relais | couper | arreter | etat) "$1" ;;
garde) garde ;;
*) sed -n '2,/^PATH=/p' "$0" | sed '$d'; exit 2 ;;
esac
