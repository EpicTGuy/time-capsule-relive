# Contributions proposées à TimeCapsuleSMB

Brouillons, **non envoyés** : à valider avant toute publication (issue d'abord, puis PR).

## 1. Point d'accroche utilisateur au démarrage (`/mnt/Flash/rc.user`) — issue #403 ouverte, PR à proposer

Issue amont : https://github.com/jamesyc/TimeCapsuleSMB/issues/403. Réponse de James (29/10) : d'accord pour NetBSD 6,
pas pour NetBSD 4 (le `rc.local` de l'image flash Apple a une taille fixe : des octets en plus écraseraient le fichier
suivant) → mettre le crochet **en tête de `boot.sh`**. Fait le 04/11 : `0001-rc-user-hook.patch` (sur `main` v3.8.4),
`rc.local` inchangé.

Vérifié le 04/11 : 360 tests démarrage/déploiement identiques avant/après ; **sur l'appareil** (A1470, NetBSD 6) :
`rc.user` créé, `tcapsule deploy --yes` réécrit `rc.local` (ligne ajoutée à la main effacée) et, après redémarrage,
les outils lancés par `rc.user` tournent ; `deploy` tout « ok ». Non testé sur NetBSD 4 (pas d'appareil).

## 2. Table des 533 propriétés ACP du firmware 7.9.1

Extraite de la table interne d'ACPd (`docs/proprietes-acp.tsv` : nom, type, attributs) + correspondance des types
(2 texte, 5 entier, 8 MAC, 13 CFB0…) et rôle des clés Wi-Fi (`docs/analyse-firmware-7.9.1.md` §4–5). Pourrait
servir à leur client ACP. Proposer d'abord en issue (« would a property table be useful? »).

## 3. Go sur NetBSD 6 (Time Capsule)

`analyse/go-netbsd6-timecapsule.patch` : permet d'écrire des outils en Go pour l'appareil (TimeCapsuleSMB utilise
du C natif). Information utile à partager dans une discussion, pas une PR.
