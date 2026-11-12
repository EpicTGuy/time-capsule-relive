# WireGuard sur la Time Capsule (29/10/2026)

| | Sans | Aujourd'hui |
|---|---|---|
| Accès au réseau de la maison depuis l'extérieur | impossible via la Time Capsule | **serveur WireGuard sur la Time Capsule** (`wg-tc`) |

## Pourquoi ce n'était « pas possible »

1. **Pas de pilote `tun`** dans le noyau Apple (`ifconfig -C` : `wlan bridge stf gif pppoe vlan lo pflog`).
   → On n'utilise pas d'interface noyau : la pile TCP/IP du tunnel est **gVisor netstack**, dans le processus.
2. **Le Go officiel ne tourne pas sur NetBSD 6** (il vise NetBSD 7+). Deux écarts trouvés sur l'appareil :
   - création de threads : `_lwp_create` → `EINVAL`. Le noyau place `uc_mcontext` à l'**octet 36** (relevé avec
     `getcontext`), Go le suppose à l'octet 40 (remplissage EABI de NetBSD 7) : tous les registres étaient décalés ;
   - `___lwp_park60` (n° 478) n'existe pas → `SIGSYS`. Remplacé par `___lwp_park50` (n° 434), qui prend une
     échéance **absolue** sur l'horloge réelle.
   → `analyse/go-netbsd6-timecapsule.patch` (75 lignes). Validé : goroutines, préemption asynchrone, ramasse-miettes,
   aléa cryptographique, sockets.
3. **wireguard-go** : le paquet `ipc` exclut NetBSD par ses contraintes de compilation →
   `analyse/wireguard-go-netbsd.patch` (ajout de `netbsd`).
4. **gVisor** : avec le mode promiscuité (relais), `HandleLocal` fait prendre toute adresse source pour une adresse
   locale et jette les paquets (`InvalidSourceAddressesReceived`) → `HandleLocal: false`.

## Fonctionnement de `wg-tc` (`outils/wg-tc/`)

- Configuration au format WireGuard habituel (`[Interface]` / `[Peer]`), plus `RelayTo = 192.168.1.0/24` pour
  limiter les destinations relayées.
- Chaque connexion TCP / flux UDP d'un pair vers le réseau local est rejoué par un vrai socket de la Time Capsule
  (comme un « subnet router » en espace utilisateur). Pas d'ICMP (ping) à travers le tunnel.
- Fichiers sur l'appareil : `/Volumes/dk2/.seconde-vie/bin/wg-tc`, configuration
  `/Volumes/dk2/.seconde-vie/wg/wg0.conf` (droits 600, contient la clé privée).
- Construction : `./outils/construire-tc.sh`.

## Mesures (V)

- Mémoire : **≈ 5 Mo** au repos, ≈ 8–13 Mo après un transfert soutenu.
- À travers le tunnel (client WireGuard dans un espace réseau isolé de serveur-maison) : page HTTP du routeur OpenWrt en 0,1 s,
  DNS du routeur OpenWrt OK, port SMB de la Time Capsule joignable, destination hors `RelayTo` refusée.
- Débit : **≈ 1,2 Mo/s (≈ 10 Mbit/s)** pour 20 Mo téléchargés depuis le Mac, pendant que la Time Capsule faisait
  aussi la sauvegarde Immich. Le chiffrement ChaCha20-Poly1305 est fait en Go pur par un Cortex-A9 à 1 GHz.
- Limite : un gros transfert SMB **vers la Time Capsule elle-même** à travers le tunnel décroche (Samba + WireGuard +
  sauvegarde sur le même processeur) ; à retester hors sauvegarde.

## Faire de la place (V)

- **Swap** : `outils/tc-swap` (appel direct de `swapctl(2)`, l'outil est absent) ; fichier de 256 Mo
  `/Volumes/dk2/.seconde-vie/swap0` accepté par le noyau. **À couper (`tc-swap off`) avant toute réparation
  ou effacement du disque.**
- **Démons inutiles arrêtés** : `afpserver` (AFP, remplacé par SMB 3) et `iCloudd` (Retour vers mon Mac, fermé
  en 2019) ; non relancés par ACPd ; ≈ 4,7 Mo.
- **restic limité à 2 connexions SMB** (au lieu de 5) : 3 processus `smbd` de ≈ 7 Mo en moins pendant les sauvegardes.

## Démarrage automatique

- `/mnt/Flash/rc.local` (géré par TimeCapsuleSMB) appelle en plus `/mnt/Flash/seconde-vie.sh` (440 octets), qui
  attend le disque puis lance `/Volumes/dk2/.seconde-vie/demarrage.sh` : swap, gardes `afpserver`/`iCloudd`,
  `wg-tc` relancé s'il s'arrête. Journal : `/mnt/Memory/seconde-vie.log`.
- Original sauvegardé : `sauvegardes/rc.local.timecapsulesmb.orig`. **Un `tcapsule deploy` réécrit `rc.local`** :
  remettre `outils/tc/rc.local` ensuite (ou, mieux, proposer un point d'accroche utilisateur à TimeCapsuleSMB).
- Test de redémarrage à faire **après** la fin de la première sauvegarde Immich.

## Reste à faire pour l'utiliser de l'extérieur

1. Sur le routeur OpenWrt : rediriger le port **UDP 51820** vers 192.168.1.20 (et donner à la Time Capsule une adresse fixe,
   déjà le cas : bail réservé .244).
2. Générer la configuration du téléphone / portable (clé, QR code) et l'ajouter comme `[Peer]`.
3. Retirer le pair de test (espace réseau `wgessai` sur serveur-maison).
