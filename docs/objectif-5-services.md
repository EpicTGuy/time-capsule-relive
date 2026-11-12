# Objectif 5 : petits services réseau sur la Time Capsule (tests du 29/10/2026)

Accès : `outils/tc-ssh.sh` (SSH root, mot de passe tiré du trousseau par SSH_ASKPASS).

## Ressources disponibles (V)

- NetBSD 6.0 evbarm, 256 Mo de RAM dont **≈ 14 Mo libres** quand Samba sert des fichiers (smbd ≈ 60 Mo au total).
- Stockage : `/` en RAM (4,7 Mo libres), `/mnt/Memory` tmpfs 16 Mo, flash persistante `/mnt/Flash` **515 Ko
  libres**, disque `/Volumes/dk2` 1,1 To libres (persistant, lancé au démarrage via le `rc.local` de TimeCapsuleSMB).
- Outils présents (crunchprog Apple) : `dnscache` et `walldns` (djbdns), `racoon` + `setkey` (IPsec IKEv1),
  `pfctl`, `tcpdump`, `iperf`, `curl`, `openssl`, `wpa_supplicant`, `wl`, `brconfig`, `natpmpd`, `rtadvd`.
  Pas de `grep`, `head`, `tr` ; `sysctl`/`ifconfig` dans `/sbin` (PATH à compléter en SSH).
- Interfaces que le noyau sait créer (`ifconfig -C`) : `wlan bridge stf gif pppoe vlan lo pflog`.

## DNS local : **faisable, testé** (V)

`dnscache` d'Apple lancé en mémoire (transfert vers le routeur OpenWrt 192.168.1.1, clients 192.168.1.0/24) :
réponses correctes depuis le Mac en 3–4 ms, **3,6 Mo de RAM**. Arrêté après le test (rien d'installé).
Pour en faire un service : script de lancement sur le disque appelé au démarrage. Limite : `dnscache` est un
cache/transfert ; des noms locaux personnalisés demanderaient `tinydns` (absent, à compiler) — le routeur OpenWrt
(dnsmasq) le fait déjà.

## WireGuard : ~~impossible~~ → **fait, voir `docs/wireguard.md`**

Premier diagnostic (conservé pour l'historique) :

Pas de pilote `tun` dans le noyau (`ifconfig tun0 create` → `SIOCIFCREATE2: Invalid argument` ; aucun cloneur
`tun`/`tap`), et wireguard-go ne prend pas NetBSD en charge. RAM libre insuffisante de toute façon.
Alternatives : WireGuard sur le **routeur OpenWrt** (OpenWrt l'intègre) ou sur serveur-maison ; sur la Time Capsule seul IPsec
IKEv1 (`racoon`) existe, ancien et peu recommandable.

## Conclusion

La Time Capsule reste avant tout **disque réseau + point d'accès/répéteur**. Services légers possibles (cache
DNS, relais) mais la mémoire est le facteur limitant tant que Samba tourne.
