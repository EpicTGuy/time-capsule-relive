# Time Capsule ReLive

*When Apple leaves, Time Capsule relives.* Une seconde vie pour l'AirPort Time Capsule d'Apple (802.11ac, 5e génération, A1470), sans la démonter.*
🇬🇧 [English version](README.md)

Apple n'entretient plus la Time Capsule depuis 2019, et macOS 27 a retiré les protocoles dont elle dépend (AFP,
SMB 1). Le matériel reste bon : point d'accès Wi-Fi 802.11ac bi-bande, ports gigabit, disque de 2–3 To. Ce projet
la garde utile, **de façon réversible**, en ajoutant des outils à côté du logiciel d'Apple au lieu de le remplacer.

Il s'appuie sur [TimeCapsuleSMB](https://github.com/jamesyc/TimeCapsuleSMB), qui apporte SSH et un Samba moderne
(SMB 3). Tout ce qui est ici est complémentaire.

## Ce que ça apporte

| Domaine | État | Quoi |
|---|---|---|
| **Partage SMB 3 / Time Machine** | ✅ via TimeCapsuleSMB | fonctionne avec macOS 27 et Linux ; 20–28 Mo/s mesurés |
| **Régler le Wi-Fi sans l'Utilitaire AirPort** | ✅ testé | `outils/tc-wifi.py` : lecture/écriture de toute la configuration Wi-Fi (propriété ACP `WiFi`), sauvegarde exacte et restauration à l'octet près |
| **Documentation du protocole ACP** | ✅ | table des **533** propriétés du firmware 7.9.1 (78 connues avant), format CFB0, clés Wi-Fi (`raSt`, `raWM`, `dWDS`…) |
| **Client et répéteur Wi-Fi avec n'importe quel routeur** | ✅ testé | une radio rejoint une box, un routeur ou un partage de connexion (WPA2) ; la Time Capsule y devient joignable et **partage la connexion** sur son propre Wi-Fi et sur son câble (traduction d'adresses, ~110–125 Mbit/s mesurés). Contourne les deux blocages d'Apple : pas d'adresse IP sur une radio cliente, répéteur réservé aux bornes Apple. Voir [docs/spec-nat.md](docs/spec-nat.md) |
| **Mode automatique** | ✅ testé | câble vers une box : les deux radios diffusent le Wi-Fi de la Time Capsule ; câble débranché ou vers un routeur branché par son port WAN : elle rejoint le réseau connu le mieux reçu et partage la connexion ; retour seul quand le câble revient |
| **Réseaux de confiance** | ✅ | SSH, ReLive, partage de fichiers et Bonjour ne sont relayés que sur les réseaux marqués de confiance (rien d'exposé sur un Wi-Fi d'hôtel ou public) |
| **Lancer des programmes Go sur l'appareil** | ✅ | runtime Go corrigé pour le NetBSD 6 d'Apple (threads, `_lwp_park`) : goroutines, ramasse-miettes, préemption, réseau |
| **Serveur WireGuard** | ✅ testé | `wg-tc` : WireGuard en espace utilisateur (wireguard-go + gVisor), sans `tun` noyau, ~5 Mo de RAM, ~10 Mbit/s |
| **Plus de mémoire** | ✅ | `tc-swap` : 256 Mo d'échange sur le disque (l'appareil a 256 Mo de RAM) ; arrêt des démons Apple inutiles |
| **Interface web (ReLive)** | ✅ testé | tableau de bord (disque, SMART, températures, mémoire, services, sauvegardes), réglages Wi-Fi avec sauvegarde/restauration automatiques, rejoindre un réseau, mode automatique, journaux, redémarrage — sur l'appareil, en HTTPS, ~9 Mo de RAM |
| **Tailscale** | 🧪 | se compile (réseau en espace utilisateur) ; à retester depuis la RAM (ne jamais lancer de programme depuis le disque HFS+, voir [docs/go-netbsd6.md](docs/go-netbsd6.md)) |
| **Supervision** | ✅ | sonde pour un serveur maison : disque, températures, ventilateur, Samba, âge des sauvegardes → alertes ntfy |
| **Sauvegardes chiffrées hors serveur** | ✅ exemple | restic (chiffré côté serveur) vers la Time Capsule en SMB, chaque nuit, avec rotation |
| **Lire l'ancien disque depuis macOS 27** | ✅ | client SMB 1 en lecture seule + copie parallèle reprenable des sauvegardes Time Machine |
| **Analyse du firmware** | ✅ | téléchargement/déchiffrement de l'image 7.9.1 d'Apple, extraction du système FFS, scripts Ghidra |

Écarté (voir [l'étude](docs/etude-possibilites.md)) : OpenWrt — les puces Wi-Fi BCM4360 n'ont pas de pilote libre
utilisable, on perdrait le Wi-Fi, et le flashage demande d'ouvrir l'appareil.

## Sécurité d'abord

- **Réversible** : chaque écriture sauvegarde l'état précédent et a sa commande de restauration. Rien n'est flashé.
- **Aucun code Apple distribué** : seulement nos outils, notes et correctifs. L'analyse télécharge la mise à jour
  officielle depuis les serveurs d'Apple, sur votre machine.
- ACP protège mal le mot de passe : n'utiliser ces outils que sur le **réseau local**.
- Revue de sécurité avant publication : [docs/revue-securite.md](docs/revue-securite.md).
- Sauvegardez vos données Time Machine avant toute modification (`outils/tc-smb1.py` sait les copier, même depuis macOS 27).

## Démarrage rapide

```sh
# 1. SMB 3 + SSH : suivre le README de TimeCapsuleSMB (tcapsule configure / deploy / doctor)
# 2. Ce projet
python3 -m venv .re-tools/venv && .re-tools/venv/bin/pip install pycryptodome impacket passlib
echo "TC_HOTE=192.168.1.20" > config.local           # adresse IP de votre Time Capsule
.re-tools/venv/bin/python outils/acp-lire.py          # relevé en lecture seule de tous les réglages
.re-tools/venv/bin/python outils/tc-wifi.py voir      # configuration Wi-Fi actuelle
./outils/construire-tc.sh                             # compile les outils de l'appareil (Go corrigé) dans binaires/
```

Les outils de l'appareil (ReLive, tc-pont, tc-dhcp, relais.sh) se lancent au démarrage par le point d'accroche
`/mnt/Flash/rc.user` de TimeCapsuleSMB, qui lance `outils/tc/seconde-vie.sh` puis `outils/tc/demarrage.sh` : rien n'est
écrit dans le firmware.

## Ce qu'on a appris en chemin

- **Un vrai routeur fait mieux comme répéteur.** Un routeur Wi-Fi 6 récent en mode répéteur, la Time Capsule branchée
  derrière par câble, donne 3 à 4 fois le débit de la Time Capsule seule (360–450 contre 110–125 Mbit/s mesurés). Le
  répéteur de la Time Capsule reste utile quand on n'a qu'elle.
- **Sans câble, la Time Capsule plafonne à 25–60 Mbit/s** vers un appareil Wi-Fi : son 2,4 GHz est limité à 20 MHz
  (la seule table de pays européenne de la puce n'autorise pas 40 MHz) et une radio partagée entre capter et
  diffuser perd beaucoup. Mesures : [docs/spec-nat.md](docs/spec-nat.md).

## Remerciements

[TimeCapsuleSMB](https://github.com/jamesyc/TimeCapsuleSMB) · [airpyrt-tools](https://github.com/x56/airpyrt-tools) ·
[wireguard-go](https://git.zx2c4.com/wireguard-go) · [gVisor](https://gvisor.dev) ·
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) · [REA](https://github.com/morluto/rea)

## Licence

GPL-3.0 (voir [LICENSE](LICENSE)). Le code repris de wireguard-go garde sa mention MIT.
