# État de l'art — 28/10/2026

Ce que la communauté a déjà réussi sur les Time Capsule. **V** = vérifié (source primaire lue ou test sur notre
appareil) ; **S** = supposé (presse, notes de version, à confirmer).

## 1. Contexte : pourquoi c'est urgent

- **S** macOS 26 Tahoe sauvegarde encore sur Time Capsule, mais ne peut plus *créer* une nouvelle sauvegarde (veut de
  l'APFS). [Eclectic Light](https://eclecticlight.co/2026/02/11/macos-tahoe-no-longer-fully-supports-time-capsules/)
- **S** macOS 27 « Golden Gate » retire AFP et exige SMB 2/3 : la Time Capsule d'origine (AFP + SMB 1) devient
  inutilisable depuis un Mac récent. [MacRumors](https://www.macrumors.com/2026/06/17/macos-27-golden-gate-kills-time-capsule-support/),
  [MacRumors (rappel)](https://macrumors.com/2026/09/16/macos-27-ends-time-machine-backups-time-capsule)

## 2. Disque réseau SMB 3 — projet TimeCapsuleSMB (objectif 2)

[github.com/jamesyc/TimeCapsuleSMB](https://github.com/jamesyc/TimeCapsuleSMB) — James Chang, licence GPL-3.0, très
actif en 2026 (v3.6.0, Samba 4.25). Couverture : [The Register](https://www.theregister.com/software/2026/05/09/macos-27-threatens-to-bury-time-capsule-foss-brings-a-shovel/5234824),
[OSnews](https://www.osnews.com/story/144845/apple-wants-to-kill-your-time-capsule-but-they-run-netbsd-so-they-cant/),
[IT-Connect (fr)](https://www.it-connect.fr/macos-27-menace-les-time-capsule-timecapsulesmb-est-la-pour-les-sauver/),
[TidBITS](https://talk.tidbits.com/t/method-to-add-smb3-to-apple-time-capsules/33436).

D'après le README (lu le 28/10/2026) :

- **S** Testé par l'auteur sur **A1470** (notre modèle probable). La 5e génération tourne sous **NetBSD 6** et relance
  Samba seule au démarrage (les générations 1-4, NetBSD 4, non).
- **S** Active lui-même le **SSH** via un client ACP en Python 3, puis redémarre l'appareil.
- **S** Où vont les fichiers : Samba sur le disque dur (dossier `.samba4`), petit lanceur dans `/mnt/Flash`
  (`rc.local`, `boot.sh`, config, binaire `service` ; ~900 Ko libres). Le reste du système est effacé à chaque
  redémarrage ; seul `/mnt/Flash` persiste. Samba est copié en RAM au démarrage.
- **S** Mot de passe SMB = mot de passe de la Time Capsule ; invités désactivés ; tout utilisateur mappé sur `root`.
  À garder **strictement sur le réseau local**.
- **S** Les sauvegardes Time Machine existantes sont reprises sans effacement (contredit en partie la presse, qui parle
  d'une nouvelle chaîne de sauvegarde : **à vérifier sur une copie**).
- **S** Marche arrière : `tcapsule uninstall` (avec `--dry-run`), ou à la main (supprimer 5 fichiers de `/mnt/Flash`
  et `.samba4`, redémarrer) ; `tcapsule flash --restore` remet le logiciel Apple d'origine.
- **S** Avertissements : le déploiement **peut réinitialiser les réglages Apple** (Wi-Fi à refaire) ; effacer le disque
  dans l'Utilitaire AirPort supprime l'installation ; préférer l'Ethernet, couper VPN/pare-feu pendant l'installation.
- Prérequis : Mac macOS 14+ (appli graphique ou CLI) ou Linux (CLI), Python 3.9+, OpenSSH ≥ 8.4.

**Conclusion** : l'objectif 2 et la moitié de l'objectif 3 (SSH) sont déjà résolus par la communauté. Inutile de
recompiler Samba nous-mêmes ; mieux vaut utiliser, vérifier et éventuellement contribuer à ce projet.

## 3. Accès d'administration (SSH) — objectif 3

- **S** Méthode connue depuis 2018 : propriété ACP `dbug` = `0x3000`, puis redémarrage → OpenSSH sur le port 22,
  connexion `root` avec le mot de passe de l'appareil. [jcs.org](https://jcs.org/2018/06/12/airport_ssh)
  (même famille d'appareil : NetBSD 6.0, Cortex-A9 1 GHz, 256 Mo de RAM).
- **S** Le mot de passe SSH n'est comparé que sur ses 8 premiers caractères (noté par TimeCapsuleSMB).
- **V** Sur notre appareil, le port 22 est **fermé** aujourd'hui (test du 28/10/2026).
- Retour arrière supposé : remettre `dbug` à sa valeur d'origine (à **lire et noter avant**) ou réinitialisation.

## 4. Remplacer l'Utilitaire AirPort (protocole ACP) — objectif 1

- **S** [airpyrt-tools](https://github.com/x56/airpyrt-tools) (archivé, Python 2.7) : lit/écrit les propriétés ACP.
  Envoie le mot de passe quasiment en clair (pas de SRP) → à n'utiliser que sur le réseau local.
- **S** [node-acp](https://www.npmjs.com/package/node-acp) (Node.js) : même protocole, avec chiffrement. Non lu en détail
  (page inaccessible au moment de la recherche).
- **S** TimeCapsuleSMB embarque un client ACP Python 3 moderne : candidat naturel pour nos outils de réglage.
- **Non trouvé** : un outil libre documenté pour régler **pont** (« Mode routeur : désactivé ») et **répéteur**
  (« Étendre un réseau sans fil ») sans l'Utilitaire AirPort. Il faudra identifier les propriétés ACP correspondantes
  (lecture avant/après un réglage fait avec l'Utilitaire AirPort, puis comparaison) — travail original, publiable.
- Rappel : le mode « étendre » d'Apple ne fonctionne en principe qu'avec un réseau principal Apple ; avec le routeur OpenWrt (non
  Apple), le répéteur pur risque d'être impossible. Alternative réaliste : **relier la Time Capsule en Ethernet** (ou
  CPL) et l'utiliser en **point d'accès en mode pont**. À confirmer.

## 5. Analyse du logiciel 7.9.1

- **S** Les fichiers `.basebinary` sont chiffrés (AES-CBC, clé par modèle cachée dans `crunchprog`, 2 conteneurs
  imbriqués). Outil de déchiffrement publié avec airpyrt-tools, mais avec les clés de quelques modèles seulement.
  [Embedded Ideation](https://www.embeddedideation.com/page2/)
- Avec le SSH, on peut lire directement le système en marche (plus simple que déchiffrer l'image) : Ghidra/REA
  deviennent utiles surtout pour comprendre `ACPd` et les propriétés de pont/répéteur.

## 6. Relevé réseau du 28/10/2026 (lecture seule)

- **V** Appareil joignable (ping OK). Ports ouverts : 139, 445, 548, 5009, 10000. Port 22 fermé.
- **V** Annonce Bonjour `_adisk._tcp` « AirPort Time Capsule Wi-Fi » (disque Time Machine), à côté de « serveur-maison Time
  Machine » et « serveur ».
