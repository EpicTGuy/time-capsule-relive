# Sauvegarde chiffrée d'Immich vers la Time Capsule (29/10/2026)

| | Sans | Aujourd'hui | Après |
|---|---|---|---|
| Photos Immich (213 Go d'originaux) | une seule copie, sur serveur-maison | idem | + copie **chiffrée** sur la Time Capsule, chaque nuit, avec historique |

## Fonctionnement

- **restic 0.14** sur serveur-maison, dépôt `rclone:tcsmb:Data/immich-restic` (format v2, compression auto).
  restic chiffre tout sur serveur-maison (AES-256-CTR + Poly1305) avant l'envoi : la Time Capsule ne stocke que des blocs
  illisibles sans le mot de passe du dépôt.
- Transport : backend **SMB natif de rclone** (remote `tcsmb`, mot de passe de la Time Capsule masqué dans
  `/root/.config/rclone/rclone.conf`, droits 600). Pas de montage CIFS.
- Sauvegardé : `/home/yunohost.app/immich` **sauf** `encoded-video` et `thumbs` (régénérables) → originaux
  (`upload`, `library`, `profile`) + dumps quotidiens de la base (`backups`, faits par Immich à 2 h).
- Rotation : 7 jours, 5 semaines, 12 mois, 3 ans (`restic forget --prune`).
- Planification : `sauvegarde-immich.timer` chaque nuit à 3 h 30 (± 15 min), rattrapage si serveur-maison était éteint.
- Fichiers (sources dans `outils/serveur/`) : `/usr/local/sbin/sauvegarde-immich.sh`,
  `/etc/systemd/system/sauvegarde-immich.{service,timer}`, journal `/var/log/sauvegarde-immich.log`.

## Mot de passe du dépôt — IMPORTANT

`/root/.config/restic/immich.pass` (généré aléatoirement, droits 600). **Sans lui, la sauvegarde est
irrécupérable.** En garder une copie hors de serveur-maison (Vaultwarden est hébergé sur serveur-maison : il faut aussi une copie
papier ou sur un autre appareil).

## Commandes utiles (sur serveur-maison)

```sh
sauvegarde-immich.sh                     # sauvegarde maintenant
sauvegarde-immich.sh restic snapshots    # liste des sauvegardes
sauvegarde-immich.sh verifier            # relit 5 % des données pour contrôle
sauvegarde-immich.sh restic restore latest --target /tmp/restauration --include '/home/yunohost.app/immich/upload/…'
systemctl list-timers sauvegarde-immich.timer
```

## Mesures

- Première sauvegarde (29/10/2026, 8 h 39 → 14 h 26) : 30 345 fichiers, 212,6 Gio, 5 h 47, succès (snapshot 4e3b3382).
- Cache restic : `RESTIC_CACHE_DIR=/var/cache/restic` (sans lui, chaque sauvegarde relit tout le dépôt).
- Place sur la Time Capsule avant : 1,15 To libres.
