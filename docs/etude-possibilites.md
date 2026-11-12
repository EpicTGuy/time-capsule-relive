# Que faire d'autre avec une AirPort Time Capsule ? (étude du 29/10/2026)

## Le matériel, tel que relevé sur l'appareil

| | |
|---|---|
| Processeur | Broadcom **BCM53018** (famille Northstar), **1 cœur** Cortex-A9 à 1 GHz actif (NEON, VFPv3), 512 Ko de cache L2 |
| Mémoire | 256 Mo (229 Mo utilisables) + **256 Mo de swap** sur disque (ajouté) |
| Wi-Fi | 2 × Broadcom **BCM4360** (802.11ac 3×3, selon une revue matérielle) |
| Stockage | disque 2 To (SATA), flash interne ~1 Mo libre |
| Réseau | 1 WAN + 3 LAN gigabit, USB 2.0 (imprimante) |
| Système | NetBSD 6.0 d'Apple (2019), sans compilateur ni outils courants |

Ce qui débloque presque tout : **le Go corrigé pour NetBSD 6** (`analyse/go-netbsd6-timecapsule.patch`). Tout
programme écrit en Go peut désormais y tourner, sans toucher au système d'Apple.

## Remplacer le système : OpenWrt ou NetBSD récent ? → **non pertinent**

- **OpenWrt** gère la famille BCM53xx (cible `bcm53xx`), mais **les puces Wi-Fi BCM4360 n'ont pas de pilote libre
  utilisable en point d'accès** (ni b43 ni brcmfmac) : on perdrait le Wi-Fi, c'est-à-dire l'objectif n° 1.
- Le chargeur de démarrage est un **CFE d'Apple** ; sans port série (il faut ouvrir l'appareil, exclu par les
  règles du projet), une erreur de flashage rend l'appareil inutilisable.
- Personne ne l'a fait publiquement pour ce modèle ; le forum OpenWrt ne couvre que les modèles Kirkwood plus
  anciens ([forum OpenWrt](https://forum.openwrt.org/t/adding-openwrt-support-for-apple-airport-extreme-time-capsule-kirkwood/62284)).
- **NetBSD récent** : même problème de Wi-Fi.

**Conclusion** : garder le système d'Apple (Wi-Fi, ACP, disque) et **ajouter** nos programmes à côté, comme
TimeCapsuleSMB et `wg-tc`. C'est réversible, sans risque de briquer l'appareil.

## Idées classées (intérêt / faisabilité / RAM)

| # | Idée | Intérêt | Faisabilité | RAM | Remarque |
|---|---|---|---|---|---|
| 1 | **Répéteur Wi-Fi / pont** (objectif 1) | ★★★ | en cours | 0 | DWDS natif, test n° 3 à faire |
| 2 | **Supervision** : petit exportateur Go (disque, températures, ventilateur, Samba, WireGuard) + alertes ntfy vers serveur-maison | ★★★ | facile | ~5 Mo | données déjà lisibles par ACP |
| 3 | **Tailscale** (mode `userspace-networking`, sans tun) | ★★★ | probable (même correctif Go) | ~30 Mo | accès distant sans ouvrir de port, très demandé par la communauté |
| 4 | **Accélérer WireGuard** : ChaCha20-Poly1305 en assembleur NEON pour ARM 32 bits | ★★ | moyen | 0 | x/crypto n'a pas d'assembleur arm32 ; gain attendu ×2–3 |
| 5 | **rest-server** (restic) : sauvegardes par HTTP au lieu de SMB | ★★ | facile (Go) | ~10 Mo | moins de charge CPU que Samba pour restic |
| 6 | **Point d'accroche utilisateur** dans TimeCapsuleSMB (`rc.user`) | ★★ | facile (PR) | 0 | évite qu'un `deploy` efface nos lancements |
| 7 | **Résolveur DNS de secours** (dnscache d'Apple, ou Blocky en Go) | ★ | fait (test) | 4–30 Mo | un AdGuard existe déjà (192.168.1.50) : seulement en secours |
| 8 | AdGuard Home | ★ | possible (Go) | 50–100 Mo | redondant avec l'AdGuard existant, lourd pour 256 Mo |
| 9 | Syncthing | ★ | possible (Go) | 60–150 Mo | gourmand en CPU et en RAM |
| 10 | Serveur d'impression (USB) | ★ | natif (`printd`) | 0 | déjà présent |

## Projet public

- Dépôt public (licence GPL-3.0, compatible avec TimeCapsuleSMB ; le code repris de wireguard-go reste MIT) :
  outils ACP, analyse du firmware (sans code Apple), correctif Go NetBSD 6, `wg-tc`, `tc-swap`, scripts, guide.
- Contributions possibles à TimeCapsuleSMB : table des 533 propriétés ACP, point d'accroche `rc.user`, module
  optionnel WireGuard, correctif Go (aussi utile pour d'autres projets NetBSD 6).
- À retirer avant publication : adresses IP, noms de réseaux, noms de personnes, chemins personnels.
