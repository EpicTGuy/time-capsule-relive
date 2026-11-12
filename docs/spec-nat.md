# Spec — partage de connexion par traduction d'adresses (NAT) dans tc-pont

*11/11/2026. Remplace le « routeur virtuel » gVisor du mode relais.*

## Objectif

Partager la connexion du Wi-Fi client (box) sur le Wi-Fi de la Time Capsule et sur son câble, avec le débit le plus
haut que permet le processeur, et un code plus court que l'actuel.

## Constat (mesures du 11/11/2026)

- Lien Wi-Fi avec la box à 1053 Mbit/s ; fibre de 270 à 480 Mbit/s mesurés ; partage : 21 Mbit/s, processeur saturé.
- Chaque paquet traverse deux piles TCP complètes (gVisor côté appareils, gVisor côté box), et une copie entre elles.

## Principe

- Le **noyau** prend `10.42.42.1` sur bridge0 : DHCP (dhcpd), ARP, ping, et les services de la Time Capsule (SMB,
  SSH, ReLive) au débit natif. Son routage reste coupé (`ip.forwarding=0`) : il ignore les paquets pour l'extérieur.
- **tc-pont** lit ces paquets par BPF (Wi-Fi de la Time Capsule et câble), remplace l'adresse et le port source par
  les siens (ports 32768–65535), ajuste les sommes de contrôle par différence (RFC 1624), et les écrit sur le Wi-Fi
  client vers la MAC du routeur. Les réponses font le chemin inverse. TCP, UDP, ping, et les erreurs ICMP liées
  (« fragmentation nécessaire » : sinon certaines connexions se bloquent).
- La pile gVisor du Wi-Fi client reste, pour la Time Capsule elle-même (services, Bonjour) ; elle garde les ports
  16000–32767.
- DNS : dhcpd annonce 10.42.42.1 ; tc-pont y écoute (socket du noyau) et relaie au serveur de la box. Les
  appareils gardent ainsi le même serveur quel que soit le réseau rejoint.

## Contraintes non négociables

- Réversible : rien dans la flash ; `relais.sh couper` rend l'état d'avant.
- Ne jamais servir d'adresses sur un câble qui mène à un réseau (sonde DHCP, inchangée).
- Les appareils du réseau de la box ne peuvent joindre les appareils partagés que par une traduction qu'ils ont
  ouverte eux-mêmes (comme une box).
- Pas de secret dans le code ni les journaux.

## Hors périmètre

IPv6, fragments IP (abandonnés : MTU 1500 des deux côtés), redirection de ports entrants, UPnP.

## C'est fini quand…

1. Le routeur OpenWrt branché en WAN sur la Time Capsule a Internet ; iPhone et Mac naviguent par lui (l'utilisateur vérifie).
2. Le débit est mesuré et noté (avant : 21 Mbit/s).
3. Un appareil sur le Wi-Fi de la Time Capsule navigue aussi.
4. Tout revient seul après un redémarrage ; câbles remis à l'origine → deux radios en Wi-Fi.
5. Tests unitaires de la traduction (sommes de contrôle, aller-retour) au vert.

## Plan

1. `nat.go` (traduction, table, expiration) + tests sur Mac.
2. `main.go` : branchement côté Wi-Fi client ; suppression de `lan.go` (routeur gVisor).
3. `relais.sh` : `10.42.42.1` au noyau ; relais DNS de tc-pont annoncé par dhcpd.
4. Déploiement en deux temps : binaire en RAM d'abord (l'ancien reste sur le disque), puis disque une fois validé.

## Résultats (11/11/2026, routeur OpenWrt en WAN sur la Time Capsule, cliente 5 GHz de la box)

| Mesure | Routeur virtuel gVisor | Traduction d'adresses |
|---|---|---|
| Descendant (routeur OpenWrt, après-midi) | 21 Mbit/s | 110–128 Mbit/s |
| Montant | — | 66 Mbit/s |
| Ouverture de connexion vers la box | 70 ms | 5 ms |
| Redémarrage → Internet revenu seul | — | 148 s |

Où est le plafond (~125 Mbit/s, quatre flux en parallèle compris) :
- pas le processeur : une boucle de calcul lancée à côté ne change rien au débit (la Time Capsule a deux cœurs,
  Go n'en voit qu'un) ;
- pas le câble : routeur OpenWrt → noyau de la Time Capsule, 391 Mbit/s ;
- pas de trames perdues par BPF (compteur BIOCGSTATS à zéro) ;
- reste le Wi-Fi client (radio 5 GHz en mode APSTA, canal DFS 108) ou la box : à mesurer avec un appareil
  posé sur le Wi-Fi de la box au même endroit (⏳ quand l'occasion se présente).

Essayés sans gain mesurable, retirés : une seule boucle `select` pour toutes les interfaces (avec ou sans fil
réservé), tampons BPF de 1 Mo. Le soir, les serveurs de test varient de 75 à 130 Mbit/s : comparer de jour, ou
avec un serveur de la maison côté box.

## Répéteur sans câble : mesures du 12/11/2026 (iPhone, LibreSpeed sur serveur-maison, trajet local)

Time Capsule cliente du routeur OpenWrt, iPhone au même endroit, données cellulaires coupées (sinon l'iPhone bascule en 5G
dès que le Wi-Fi n'a plus de passerelle : c'est ce qui faussait les premiers essais).

| Montage | Réception | Envoi | Délai |
|---|---|---|---|
| Référence : iPhone directement sur MonWiFi-5G | 243 Mbit/s | 192 Mbit/s | 2 ms |
| C — capte en 5 GHz, diffuse en 5 GHz sur la même radio (réseau invité lancé à la main, canal 108) | 42 | 13 | 4 ms |
| A — capte en 5 GHz, diffuse en 2,4 GHz (canal 1, 20 MHz) | 25 | 49 | 4 ms |
| B — capte en 2,4 GHz (lien 144 Mbit/s), diffuse en 5 GHz (canal 36, 80 MHz) | 59 | 18 | 4 ms |

Lecture : sans câble, la liaison en 2,4 GHz (étroite, 20 MHz) limite A et B ; la radio partagée limite C, bien plus
que « divisé par deux ». Avec un câble vers le routeur (routeur OpenWrt en WAN), la Time Capsule ne fait que capter :
110–128 Mbit/s mesurés. Piste : 2,4 GHz en 40 MHz (`allow_ht40=0` aujourd'hui dans la config hostapd d'ACPd).

Panne trouvée pendant ces mesures : sans câble, le dhclient d'ACPd retire toutes les adresses de bridge0,
10.42.42.1 comprise (la passerelle des appareils) ; la surveillance de relais.sh la remet désormais.

## Comparaison avec le mode répéteur du routeur OpenWrt (12/11/2026)

routeur OpenWrt (routeur OpenWrt, Wi-Fi 6) en mode « Répéteur » sur le 5 GHz de la box (lien 1201 Mbit/s), câble box
débranché : **360 à 450 Mbit/s** vers Internet, contre 110 à 128 quand la Time Capsule capte la box et que le
routeur OpenWrt est branché derrière. Montage retenu chez l'utilisateur : box ~ Wi-Fi ~ routeur OpenWrt (répéteur) — câble — Time Capsule
(configuration d'origine : disque Time Machine, Wi-Fi d'appoint). Le répéteur de la Time Capsule reste le secours
(sans routeur OpenWrt), et l'apport pour qui n'a qu'une Time Capsule.
