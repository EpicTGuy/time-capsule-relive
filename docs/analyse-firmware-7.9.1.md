# Analyse du logiciel 7.9.1 (Time Capsule 802.11ac, produit 119)

Analyse hors ligne, sans toucher à l'appareil. Aucun fichier d'Apple n'est publié : seulement la méthode, nos outils
et nos constats. **V** = vérifié par nous ; **H** = hypothèse à confirmer sur l'appareil.

## 1. Obtenir le système de fichiers (reproductible)

```sh
./outils/install-re-tools.sh                         # Ghidra, JDK, Node, REA dans .re-tools/
python3 -m venv .re-tools/venv && .re-tools/venv/bin/pip install pycryptodome
.re-tools/venv/bin/python outils/firmware-extraire.py # télécharge et déchiffre 7.9.1 depuis Apple
# décompression : flux gzip à l'offset 0x8164 de la charge utile → noyau de 22,6 Mo
python3 outils/ffs1-extraire.py binaires/firmware/gz_8164.bin binaires/rootfs-7.9.1
```

- **V** Fichier Apple : `apsu.apple.com/data/119/…/7.9.1.basebinary`, 7 893 428 octets,
  sha256 `6783758c0d48ec533d209dbcf97dac7fde549165c4953a2e9005bf89a51e5639`.
- **V** Deux conteneurs « basebinary » imbriqués : l'externe en clair, l'interne chiffré (AES-CBC, clé « j28-79100 »
  fournie par TimeCapsuleSMB).
- **V** La charge utile est un noyau ARM auto-décompressant ; le flux gzip donne `NetBSD 6.0 … Mon Apr 29 18:35:13
  PDT 2019` (projet interne Apple « J28 », AirPortFW-79100.2).
- **V** Le système racine est une image **FFS v1** (UFS1, petit-boutiste) embarquée dans le noyau (md_root) à
  l'offset 0x5616e0 : blocs 4096, fragments 512, 2 groupes de cylindres, **1354 entrées**.
- **V** Presque tous les programmes sont **un seul exécutable « crunchprog »** de 10 281 308 octets (ELF ARM EABI4,
  statique, sans symboles), lié sous de nombreux noms : `/sbin/ACPd`, `/usr/bin/acp`, `/sbin/hostapd`, `/sbin/wl`,
  `/sbin/acp-update-network`, `/usr/sbin/tcpdump`…
- **V** Aucun script ne règle le Wi-Fi : `/etc/rc.d/acpd` lance seulement `/sbin/ACPd`. Toute la configuration réseau
  vient d'ACPd, qui lit sa configuration dans `/mnt/Flash/ACPData.bin`.

## 2. Table des propriétés ACP

- **V** ACPd contient une table de **533 propriétés** (adresse fichier 0x8e72c0 à 0x8e8bc8, entrées de 12 octets :
  nom sur 4 lettres, type, attributs). Airpyrt n'en décrivait que 78, toutes présentes ici.
  → `docs/proprietes-acp.tsv`.
- **V** Correspondance des types (recoupée avec airpyrt) : 2 = texte, 5 = entier 32 bits, 8 = adresse MAC,
  13 = liste Apple (plist binaire), 10 = action (ex. `acRB` = redémarrer).
- **H** Attribut `0x80` = propriété par radio (`raNm`, `raWM`, `raCh`…).
- Propriétés Wi-Fi clés, rôle à confirmer par lecture avant/après : `raWM` (mode sans fil ?), `raMd` (mode radio ?),
  `raWB`, `raDS`, `raRo`, `raSt`, `raEA`, `raCh`, `raNm` (nom du réseau), `waCV`/`waIn` (mode WAN / routeur).

## 3. Répéteur Wi-Fi : ce que le firmware sait faire

- **V** Le module `hostap` intégré gère trois façons de relier deux points d'accès :
  - **DWDS (« Dynamic WDS » Broadcom, trames à 4 adresses)** : messages « DWDS caps supports *4 ADDRESS
    AGGREGATION* », « proposed BSS is DWDS Master ». C'est vraisemblablement ce qu'utilise « Étendre un réseau ».
  - **WDS « legacy »** (lien statique par adresse MAC du partenaire) : « Init Legacy WDS », « Legacy WDS partner »,
    compatible WEP / WPA-PSK / WPA2-PSK.
  - **Mode station (STA)** : « RPC -> ACPd, STA Status ».
- **V** Options de lancement correspondantes : `-dwds`, `-wdslegacy`, `-apbridge`.
- **V** Le binaire `wl` (outil Broadcom de bas niveau) est présent : réglages fins possibles par SSH.
- **H** Piste A (OpenWrt, comme le routeur OpenWrt) : un point d'accès OpenWrt avec `option wds '1'` accepte un client à
  4 adresses ; si le DWDS Broadcom de la Time Capsule s'y associe, on obtient un vrai répéteur transparent.
- **H** Piste B : WDS legacy face à un routeur qui le propose encore (anciens Broadcom, certaines box).
- `dwds`, `wdslegacy`, `apbridge` sont des options d'`ifconfig` (pilote 802.11 NetBSD), pas de `hostapd`.

## 4. Configuration d'une radio, d'après ACPd (Ghidra)

Fonctions analysées (adresses dans ACPd 7.9.1) : `0x2a4ee0` applique la configuration d'une radio ; `0x2a6b60`
convertit l'ancienne configuration (propriétés 4 lettres) vers le nouveau format (dictionnaire `WiFi` → `radios`,
une entrée par radio, clés de même nom). Pseudo-code annoté produit par `analyse/ghidra-scripts/XrefDecomp.java`
et `analyse/annoter-pool.py` (hors dépôt : dérivé du code Apple).

| Clé | Type | Rôle déduit du code | Statut |
|---|---|---|---|
| `raSt` | entier | rôle de la radio : 0 = point d'accès, 1 = **client Wi-Fi** (sinon repli point d'accès) | **V** code, à tester |
| `dWDS` | booléen | WDS dynamique Broadcom (drapeau d'interface 0x40000000) ; vrai par défaut | **V** code |
| `dwFl` | entier | options DWDS (le bit 2 change le comportement du lien) | **H** |
| `wdFl` | entier | options du WDS « legacy » | **H** |
| `raNm` | texte (≤ 34) | nom du réseau (SSID) | **V** |
| `raWM` | entier 0–12 | **type de sécurité** : 0 = aucune ; trois familles {1, 9, 11}, {2, 10, 12}, {3…8} ; 10 → 9 et 12 → 11 selon la clé. Relevé chez nous : **5** avec mot de passe (WPA2 Personnel probable) | **V** structure + relevé |
| `raWE` | données (≤ 63) | clé WEP | **H** |
| `raCr` | texte (≤ 63) | mot de passe WPA | **H** |
| `raCh` | entier | canal | **V** |
| `raMd` | entier | mode radio (b/g/n/ac…), défaut 10 ou 6 selon la bande | **V** défaut |
| `raCl` | booléen | réseau fermé (SSID masqué) | **H** |
| `raEA` | booléen | inconnu (lié à la sécurité) | ? |
| `raRo` | booléen | itinérance / roaming | **H** |
| `pref_bssid` | MAC | point d'accès préféré pour le mode client | **V** |

**Le répéteur, tel que le code le construit** (**V** structure, à tester) : quand la radio est en mode client
(`raSt` = 1) avec `dWDS` actif, ACPd crée une interface point d'accès virtuelle sur la même radio, puis la relie au
lien client (`ifconfig … link1 link2`, pont). Aucun contrôle « routeur principal Apple » n'apparaît dans cette
fonction. Seul garde-fou vu : un indicateur global (lu par `0x2900e0`) et un état 6 du démon interdisent le mode
client (on retombe en point d'accès) — rôle à identifier.

**Point critique pour un routeur non Apple** : en DWDS, la Time Capsule attend probablement que le point d'accès
principal annonce l'élément Broadcom « DWDS » dans ses balises (« proposed BSS is DWDS Master »). Un OpenWrt
mt76 n'annonce pas cet élément, mais `hostapd` peut en ajouter un (`vendor_elements`). Pistes de test, dans l'ordre :
1. routeur OpenWrt avec `option wds '1'` seul ;
2. si la Time Capsule reste en 3 adresses : ajouter au routeur OpenWrt un `vendor_elements` imitant l'élément DWDS
   (format à extraire du module hostap) ;
3. à défaut : WDS « legacy » (`wdFl`) ou mode client simple + relais.

## 5. Lecture ACP sur l'appareil (28/10/2026, lecture seule)

`outils/acp-lire.py` : **165 propriétés lues sur 533**. Les autres répondent par une erreur :
- `-0xa` : propriété inconnue ou désactivée sur ce modèle (ex. `dbug`, ce qui laisse penser que le SSH
  n'a jamais été activé) ;
- `-0x1a74` : propriétés **par radio** (`raSt`, `raWM`, `raNm`…), qu'on ne peut pas lire une par une.

**La configuration Wi-Fi complète se trouve dans la propriété `WiFi`** (format CFB0, décodé par `outils/cfb.py`) :
`{"radios": [ {radio 5 GHz}, {radio 2,4 GHz} ]}`. Chaque radio contient toutes les clés du § 4, plus
`legacywds` (liste des partenaires du WDS classique), `vaps` (réseau invité : `Mode` 6, `Enabled`…), `phymodes`,
`country`/`iso_cc`/`sku`. **V** Les 24 propriétés CFB0 relues se réencodent octet pour octet : on peut écrire une
configuration modifiée et revenir exactement à l'originale.

État relevé (**V**) :
- mode **pont** (`waCD` = `lan`, interface `bridge0`, adresse 192.168.1.20 donnée par le routeur OpenWrt 192.168.1.1) ;
- deux radios en **point d'accès** (`raSt` = 0), canaux 36 et 1, même SSID, `raWM` = 5, `dWDS` = vrai,
  `wdFl` = `dwFl` = 0, réseau invité désactivé → la Time Capsule est **reliée au routeur OpenWrt par câble** ;
- `syAM` = `TimeCapsule8,119`, chargeur de démarrage Apple CFE (Broadcom), disque `wd0` de 2 To en HFS (`MaSt`) ;
- supervision possible **sans SSH** : `MaSt` (disques, place), `sySI` (ventilateur, températures), `sySt`
  (problèmes signalés), `syUT` (temps depuis le démarrage).

## 6. Test réel n° 1 du répéteur (28/10/2026, 21 h 48 – 22 h 25)

Outil : `outils/test-repeteur.py` (version 1). Radio 5 GHz (`radios[0]`) passée en client (`raSt` = 1) de
« MonWiFi-5G » (routeur OpenWrt, canal 108, WPA2 Personnel), DWDS actif, **canal laissé à 36**. Radio 2,4 GHz inchangée.

- **V** L'écriture de `WiFi` (CFB0) + `acRB` est acceptée ; la Time Capsule redémarre en 47 s avec la nouvelle
  configuration (Bonjour annonce `raSt=1`, `raNm=MonWiFi-5G`).
- **V** Câble débranché : **aucune association en 5 min** (DHCP `reason=FAIL` toutes les ~70 s dans `logm`),
  problème **`raNN`** dans `sySt` (et dans l'annonce Bonjour `prob=raNN`).
- **V** Câble rebranché : bail DHCP **.188** obtenu par le câble, avec la **MAC de la radio 5 GHz**
  (`AA:BB:CC:DD:EE:FF`) au lieu de la MAC Ethernet → la réservation .244 du routeur OpenWrt ne s'applique plus. Pas de boucle
  constatée (0 % de perte, latence normale).
- **V** Elle voyait bien « MonWiFi-5G » (scan `raSR` : canal 108, signal fort ; le routeur OpenWrt annonce le pays « DE »
  avec des informations de canaux 802.11d curieuses).
- **V** Restauration par `tc-wifi.py restaurer` : retour en 55 s sur .244, configuration relue **identique octet
  pour octet**, plus aucun problème. La marche arrière est validée.
- **H** Cause principale : canal client figé à 36 alors que le routeur OpenWrt émet sur 108. Le code `raNN` signifierait
  « réseau à rejoindre introuvable ».

Leçons pour l'outil : en mode client, chercher la Time Capsule par Bonjour (adresse changeante) ; régler le canal.
Test n° 2 : radio 2,4 GHz client de « MonWiFi » (canal 10, sans DFS), radio 5 GHz en point d'accès.

### Tests n° 3 à 5 (30/10/2026, 8 h 40 – 9 h 10)

routeur OpenWrt routeur OpenWrt (puce MediaTek, OpenWrt) : « MonWiFi-5G » canal 108 (DFS, HE160), « MonWiFi » canal 10 (HE40),
WPA2 Personnel (`psk2`). Journal du routeur OpenWrt lu par SSH (`dmesg`/`logread`) pendant chaque essai.

| Test | Radio | Canal | DWDS | Côté routeur OpenWrt | Côté Time Capsule |
|---|---|---|---|---|---|
| 3 | 5 GHz | 108 (auto) | oui | **aucune** tentative de connexion | `raNN`, liste des liens vide |
| 4 | 2,4 GHz | 10 | oui | **aucune** tentative de connexion | `raNN`, liste des liens vide |
| 5 | 2,4 GHz | 10 | **non** | **association acceptée** (33 fois), puis « 4Way-MSG1 timeout » → désauthentification | `raNN` ; lien `wlan1` en `opmode sta` vers le BSSID du routeur OpenWrt, 0 paquet de données |

- **V** Avec DWDS actif, la Time Capsule ne tente même pas de rejoindre un routeur non Apple, quel que soit le
  canal ou la bande : elle attend sans doute l'élément Broadcom « DWDS Master » dans les balises (cf. § 4).
- **V** Sans DWDS, la radio rejoint le routeur OpenWrt (le matériel sait faire client Wi-Fi), mais ne répond jamais au
  message 1 de la poignée de main WPA2 : son demandeur (supplicant) ne semble pas armé. Un mauvais mot de passe
  aurait donné une erreur au message 2 (MIC), pas un silence.
- **H** Pistes : valeur de `raWM` propre au mode client, autre propriété qui active le demandeur (`nas` Broadcom),
  ou incompatibilité avec les éléments 802.11ax/PMF annoncés par le routeur OpenWrt. À chercher dans ACPd (Ghidra) avant le
  prochain essai.
- **V** Restauration automatique après chaque essai : configuration relue identique octet pour octet.

**Cause trouvée (9 h 15, par SSH sur l'appareil en mode client, câble branché)** :
- ACPd lance `wpa_supplicant -D net80211 -i wlan1 -c /etc/hostap_wlan1.conf` (et `hostapd` pour les points
  d'accès). Dans ce fichier, `psk=` est **la valeur de `raWE`**, pas le mot de passe.
- **V** `raWE` = PBKDF2-HMAC-SHA1(`raCr`, `raNm`, 4096, 32) : la PSK WPA, **calculée par l'Utilitaire AirPort** et
  jamais recalculée par l'appareil. Nos outils changeaient `raNm`/`raCr` en gardant l'ancienne `raWE` → le
  demandeur répondait avec une mauvaise clé (le routeur OpenWrt l'a noté « MSG1 timeout »). Même piège pour un point d'accès :
  changer le nom ou le mot de passe sans `raWE` coupe tous les clients.
- **V** Avec `raWE` recalculée (client simple, 2,4 GHz) : association **stable**, plus aucune erreur WPA ; `wlan1`
  « associated » au BSSID du routeur OpenWrt ; `tcpdump -i wlan1` montre le trafic diffusé du réseau de la maison déchiffré.
  **Le mode client WPA2 fonctionne avec un routeur non Apple.**
- **V** La radio client n'entre pas dans le pont `bridge0` (Ethernet + radio point d'accès) : pas de boucle même
  câble branché, mais **pas d'adresse IP par le Wi-Fi** une fois le câble retiré (l'adresse reste sur `bridge0`).
  Reste à trouver le réglage « accès Internet par le Wi-Fi » (`waIn` ?) ou à relayer nous-mêmes.
- Corrigé : `tc-wifi.py` (`cle_wpa`), `test-repeteur.py` et ReLive recalculent `raWE`.
- **V** Test n° 6 (9 h 48, DWDS, 2,4 GHz, **bonne `raWE`**) : toujours **aucune** tentative d'association vue par
  le routeur OpenWrt en 6 min. Le mode DWDS d'Apple ignore un routeur non Apple, indépendamment de la clé (élément Broadcom
  « DWDS Master » attendu dans les balises, **H**). Restauration identique.

### Le verrou DWDS (30/10/2026, Ghidra + inspection sur l'appareil)

- **V** En DWDS, ACPd écrit `dwds_role=3` dans `/etc/hostap_wlan1.conf` (absent en client simple).
- **V** Le wpa_supplicant intégré (ACPd, fonction de comparaison des BSS à `0x1f87d8`) commence par :
  « si `dwds_role` = 3 et que le réseau candidat n'annonce pas DWDS → ne jamais le choisir ». C'est le verrou :
  aucune association n'est tentée vers un routeur qui n'annonce pas l'élément DWDS, d'où le silence des tests
  n° 3, 4 et 6.
- **V** L'élément annoncé par la Time Capsule elle-même (`wl -i wlan0 list_ie`, balises et réponses de sonde) :
  élément vendeur Apple (OUI `00:17:f2`), type `01`, données `00 01 01 00 00 00 07` ; soit en brut
  `dd 0b 00 17 f2 01 00 01 01 00 00 00 07`. Le dernier octet ressemble aux « capacités DWDS » lues ailleurs
  dans le code (bit 1 = agrégation complète, bit 2 = 4 adresses ; **H**). Un 2ᵉ élément Apple (type `07`)
  contient la MAC de la radio.
- **H** Deux façons de passer le verrou : (a) le routeur principal annonce cet élément (OpenWrt/hostapd :
  `vendor_elements`) et accepte les trames à 4 adresses ; (b) lancer notre propre wpa_supplicant (copie
  corrigée, depuis la RAM) sans ce test. Le routeur OpenWrt (pilote MediaTek propriétaire, pas de hostapd) ne permet pas
  (a) simplement.

- **V** Voie (b) essayée le 30/10/2026 (10 h 18, câble branché, garde-fou qui coupe dès l'association) :
  `outils/wpa-sans-verrou.py` lit `/sbin/wpa_supplicant` sur l'appareil (SHA-256 du 7.9.1 vérifié), remplace le
  branchement de refus (`beq` à `0x1f8808`) par `nop`, renvoie la copie sur le disque ; lancée depuis un tmpfs à
  la place de celle d'ACPd (qui ne la relance pas). **Résultat : en DWDS, association au routeur OpenWrt en 1 s et poignée
  de main WPA2 terminée** (« AP SETKEYS DONE » côté routeur OpenWrt). Le verrou est levé.
- Essai complet sans câble (`outils/tc/essai-dwds.sh`), 09/11/2026, 23 h 14 : **V** association DWDS au routeur OpenWrt
  et WPA2 validée sans câble (signal −11 dBm, stable) ; **V** mais rien ne passe : le routeur OpenWrt ne voit que la MAC de
  la radio, la Time Capsule (MAC Ethernet) reste injoignable. Le DWDS envoie des trames à 4 adresses que seul un
  routeur Apple (ou WDS configuré) accepte. Conclusion : avec une box ou un routeur ordinaire, le répéteur Apple
  ne peut pas fonctionner, verrou levé ou non.
- **V** Détection du câble : `bcmeth0`/`bcmeth1` restent « status: active » câble débranché (lien interne vers le
  commutateur ; aucun changement visible). Le script détecte maintenant : avant la mise en pont, le routeur OpenWrt ne
  répond plus au ping ; après, plus aucune adresse n'est réapprise sur `bcmeth0` après un vidage du pont.

### Client simple : ce que le noyau d'Apple permet (10/11/2026)

- **V** En client simple (`dWDS` faux), ACPd **met aussi wlan1 dans bridge0**. Câble branché, les diffusions
  reviennent en plusieurs exemplaires sur wlan1 (jusqu'à 8 copies vues par tcpdump) : à éviter, ou retirer wlan1
  du pont (`brconfig bridge0 delete wlan1`).
- **V** Le dhclient d'Apple (ISC 4.1) s'arrête sans message juste après `PREINIT` sur wlan1. Remplacé par
  `outils/tc-dhcp` (Go, BPF) : bail obtenu du routeur OpenWrt par le Wi-Fi (192.168.1.188) — l'émission et la réception
  Wi-Fi fonctionnent.
- **V** Mais le noyau refuse toute adresse IPv4 sur wlan1, bwl0/bwl1 (`SIOCAIFADDR: Invalid argument`) : seules
  les interfaces `bridge` en acceptent. Un pont neuf (bridge2) prend une MAC au hasard (`ac:de:48:…`) que le
  routeur rejette ; changer une adresse de liaison est refusé partout (même `ifconfig bcmeth1 link …`, même par
  ioctl `SIOCALIFADDR` direct). Ni `tun` ni `tap` dans ce noyau.
- **V** Le pont d'Apple affiche des drapeaux de membre `PROXYSTA` (0x8) et `PROXYSTA_DISCOVER` (0x10), et
  la configuration Wi-Fi d'ACPd connaît une clé cachée `pSTA` (à côté de `dWDS`, `dwFl`, `wdFl` ; lue par
  `0x29bf48`, qui ne sert qu'à l'annonce Bonjour). Mais le noyau est compilé **sans** l'option
  `IEEE80211_PROXYSTA` (symbole `_KERNEL_OPT_IEEE80211_PROXYSTA` = 0x6e074def, valeur « non définie » de
  NetBSD) : pas de « proxy STA » utilisable.
- Conséquence : pour être joignable par le Wi-Fi d'une box quelconque, il faut une pile réseau **en espace
  utilisateur** sur wlan1 (BPF, MAC de la radio, adresse obtenue par `tc-dhcp`) qui relaie vers les services
  locaux (SMB, SSH, ReLive) ; et, pour le mode relais, un mandataire transparent (pf `rdr`) au lieu du NAT noyau.
- **V** `outils/tc-pont` (Go, gVisor netstack sur wlan1 par BPF, MAC de la radio, adresse de `tc-dhcp`), lancé
  par `relais.sh joindre` (10/11/2026, câble branché, radio 2,4 GHz cliente du routeur OpenWrt) : la Time Capsule répond
  **par le Wi-Fi** en 192.168.1.188 — ping 4 ms, SSH, SMB 445 (même réponse qu'en filaire), ReLive 443 ;
  24 Mbit/s mesurés en SSH (chiffrement compris). Rien n'est modifié dans le noyau ni dans la flash.
- **V** Piège : les radios 5 GHz (wlan0, point d'accès dans bridge0) et 2,4 GHz (wlan1, client) ont la **même
  MAC**. Un paquet pour l'adresse Wi-Fi arrivé par le câble était réacheminé par le noyau (`ip.forwarding=1`)
  et tournait 64 fois routeur OpenWrt ↔ Time Capsule (+567 doublons sur 10 pings). Corrigé par une route « trou noir »
  vers l'adresse Wi-Fi (`route add -host … 127.0.0.1 -blackhole`) : 0 doublon.
- `demarrage.sh` lance `relais.sh joindre` dès que wlan1 est associée en client simple (pas en DWDS).
- **V** Sans câble (10/11/2026, 9 h 25) : tout répond par le Wi-Fi seul (ping 4 ms, SSH, SMB, ReLive) ;
  24,5 Mbit/s en SSH, limité par le chiffrement (sshd ≈ 1 cœur, tc-pont 16 %), lien radio à 144 Mbit/s.
- **V** Relais Bonjour (`tc-pont/mdns.go`), sans câble (9 h 52) : le Mac voit « AirPort Time Capsule Wi-Fi »
  en `_smb._tcp` et `_adisk._tcp` (Time Machine) et résout son nom en 192.168.1.188. Leçons : mDNSResponder
  ignore l'unicast venu de sa propre adresse mais répond à une question multicast posée depuis le port 5353
  local ; gVisor ne remet le multicast qu'aux sockets abonnés (`AddMembershipOption`) ; sur ce NetBSD 6 ni
  `SetReadDeadline` ni `Close` n'interrompent une lecture Go (→ sockets système, `SO_RCVTIMEO`). Une question
  reposée revenait par le câble et faisait boucle (toutes les 20 ms) : on ne relaie que les questions
  d'autres hôtes. Câble branché, le relais se met en pause (sinon conflit de nom d'hôte pour mDNSResponder).
- **V** Mode relais (partage de connexion), 10/11/2026, 11 h 43, sans câble : un iPhone connecté au Wi-Fi 5 GHz
  de la Time Capsule (10.42.42.100 par dhcpd) charge Wikipédia, Le Monde… par le Wi-Fi du routeur OpenWrt.
  Chemin : routeur virtuel 10.42.42.1 dans tc-pont (`lan.go`, seconde pile gVisor sur wlan0 par BPF, MAC de
  bridge0, promiscuité + usurpation), qui termine TCP et UDP (QUIC, DNS) et les rejoint par la pile du Wi-Fi
  client. 30 Mbit/s mesurés en sortie (10 Mo en 2,7 s).
- **V** Impasse pf : un `rdr` vers un mandataire local fonctionne (DIOCNATLOOK au format **Darwin** : 84 octets,
  `0xc0544417`, ports sur 4 octets, `proto_variant` à essayer pour UDP), mais le pf d'Apple renvoie des
  paquets à **somme de contrôle TCP fausse** (tcpdump : « cksum … incorrect ») que l'iPhone jette ; couper
  TSO/csum sur bridge0 n'y change rien. Symptôme : 1 500 octets échangés puis blocage.
- **V** Pendant le partage, `net.inet.ip.forwarding` est mis à 0 (sinon le noyau répond « hôte injoignable »
  aux paquets des appareils vers l'extérieur) ; dhcpd en 10.42.42.254 avec `server-identifier` explicite.
- **V** Redémarrage (10/11/2026, 12 h 00 et 12 h 03, sans câble, `reboot` par SSH) : en 30 s, Wi-Fi client,
  tc-pont, partage et routeur virtuel repartent seuls. Pièges corrigés : le dhclient d'ACPd prenait un bail au
  dhcpd du relais (`ignore booting` pour la MAC de bridge0) ; sans route par défaut, l'abonnement multicast
  « interface quelconque » échoue et les questions Bonjour partent avec la source 0.0.0.0 (adresse posée par
  ce dhclient en tête de bridge0) : abonnement et envoi sur une adresse précise, 0.0.0.0 retirée par la garde.
  Port ACP 5009 relayé aussi (administration par le Wi-Fi).
- **V** Après redémarrage, l'iPhone ne naviguait plus : en promiscuité, la pile du routeur virtuel répondait aux
  sondes ARP (« qui a 10.42.42.120 ? ») que l'iPhone fait avant d'accepter un bail DHCP ; il refusait chaque
  adresse (baux « abandoned » en série). Seules les requêtes ARP pour 10.42.42.1 atteignent désormais la pile.
- **V** Redémarrage avec l'iPhone (10/11/2026, 12 h 25) : après reconnexion au Wi-Fi de la Time Capsule (l'iPhone
  était passé sur un réseau connu pendant la coupure, comportement normal d'iOS), navigation rétablie sans
  autre intervention.
- **V** Câble rebranché (12 h 32) : en moins de 30 s le partage s'arrête (dhcpd, alias, routage rétabli), la Time
  Capsule reprend 192.168.1.20 ; 0 doublon. Le relais Bonjour lit l'état du câble noté par `relais.sh`
  (`/tmp/relais/cable`) : lancer `brconfig` depuis tc-pont (os/exec) restait bloqué sur ce NetBSD 6.
- **V** Signal 5 GHz (10/11/2026) : canal 36 = 16 dBm (40 mW), 80 MHz. Canal 116 (DFS) = 21 dBm (126 mW) mais
  la Time Capsule s'y met en 20 MHz et **l'iPhone n'arrive plus à s'y connecter** (« échec », mot de passe
  refusé alors que la clé est identique). Retour au canal 36 (copie `wifi-20261110-123830.cfb`) : connexion OK.
- **V** Autres canaux (19 h 12 – 19 h 40) : 100 → la puce reste sur 36/80 (21 dBm affichés jusqu'au redémarrage,
  puis 16) ; 132 → 40 MHz, 21 dBm, radar levé, mais même échec de l'iPhone, y compris en 802.11h strict
  (`wl spect 2`) ; journal du pilote (`wl msglevel +assoc +wsec`) vide : l'iPhone n'envoie aucune demande
  d'association sur les canaux DFS de cette Time Capsule. Pays réglementaire `DE (EU/45)`. Pas de forçage de
  puissance (limite réglementaire). Retour à 36 automatique (`wifi-20261110-191228.cfb`).
- ReLive : page « Rejoindre un réseau Wi-Fi » (scan `raSR` de wlan1, WPA2/ouvert ; WPA3 seul et entreprise
  signalés non pris en charge).
- **V** Safari (iOS 27) fait passer sa navigation par `apple-native-relay.mask.apple-dns.net` (QUIC puis TCP) :
  le relais UDP est indispensable, pas seulement TCP.

## 7. Installation de TimeCapsuleSMB (29/10/2026)

Version amont `73998f65`. Commandes (mot de passe transmis par `--password-stdin` depuis le trousseau) :
`./tcapsule bootstrap` (installe `samba` 4.25.1 par Homebrew pour `smbclient`), `tcapsule configure --no-input
--host root@192.168.1.20 --skip-discovery --enable-ssh --yes --password-stdin` (ACP `dbug=0x3000` + `acRB` →
SSH ouvert sur le port 22), `tcapsule deploy --dry-run` puis `deploy --yes`, `tcapsule doctor`.

- **V** Déploiement : Samba **4.25.0** sur l'appareil, lancé au démarrage (`/mnt/Flash/rc.local`), ports 445 IPv4/IPv6,
  Bonjour `_smb._tcp` + `_adisk._tcp` (Time Machine), partage `Data`. `doctor` : tout PASS.
- **V** Depuis le Mac (macOS 27) : `smbclient -m SMB3 //192.168.1.20/Data` liste le disque.
- **V** Réglages Wi-Fi conservés ; seul le canal 2,4 GHz a changé (1 → 11) : `raCA` = **canal automatique**
  (booléen), la Time Capsule rechoisit son canal à chaque démarrage.
- Retour arrière : `upstream/.venv/bin/tcapsule uninstall` (supprime `.samba4` et les 5 fichiers de `/mnt/Flash`,
  puis redémarre) ; SSH : remettre `dbug` à 0 par ACP.
- Le fichier `upstream/.env` contient le mot de passe en clair (conception amont) : droits 600, hors dépôt.

## 8. Mise à jour v3.8.4 et point d'accroche `rc.user` (04/11/2026)

- **Contexte** : `deploy` réécrit `/mnt/Flash/rc.local`, qui lançait aussi `seconde-vie.sh` (ligne ajoutée à la main) → perdue à chaque mise à jour.
- **Issue amont** #403 : James accepte pour NetBSD 6 mais pas dans `rc.local` (taille fixe dans l'image flash NetBSD 4) → crochet **en tête de `boot.sh`**. Branche `feat/rc-user-hook` du clone `upstream/` (60d041a4, sur v3.8.4) ; 360 tests démarrage/déploiement identiques.
- **Sur l'appareil** : `/mnt/Flash/rc.user` = `exec /mnt/Flash/seconde-vie.sh` (755) ; sauvegarde `/mnt/Flash/rc.local.bak-20261104` ; `tcapsule deploy --yes` depuis la branche → TimeCapsuleSMB **v3.8.4** installé, `rc.local` réécrit sans notre ligne, et après redémarrage `relive` + `demarrage.sh` relancés par `rc.user`. `deploy` : tout « ok ».
- ⚠️ Tant que le crochet n'est pas fusionné en amont, un `deploy` depuis `main` officiel n'appellera plus `rc.user` : redéployer depuis la branche, ou remettre la ligne dans `rc.local`.
- Réponse envoyée à James le 04/11 (« Shall I open a PR? ») ; en attente.
