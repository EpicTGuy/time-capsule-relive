# La Time Capsule en NAS (plan, 29/10/2026)

Elle est **déjà** un NAS de base : partage SMB 3 (TimeCapsuleSMB), Time Machine, sauvegardes restic, supervision.
Ce qui manque pour ressembler à un petit Synology, par ordre d'utilité :

| # | Brique | Comment | État |
|---|---|---|---|
| 1 | Partage de fichiers SMB 3 + Time Machine | TimeCapsuleSMB | ✅ |
| 2 | Santé du disque (SMART) + alertes | `atactl` d'Apple → relevé toutes les 30 min → sonde → ntfy | ✅ |
| 3 | **Interface web d'administration** (« tc-admin ») | Go, ~8 Mo : état (disque, SMART, températures, Samba, sauvegardes), réglages Wi-Fi (ACP local), redémarrage, journaux ; mot de passe de la Time Capsule, HTTPS | à faire |
| 4 | **Accès web / WebDAV aux fichiers** | Go (`x/net/webdav` + petit explorateur) : téléphone, navigateur, Finder sans SMB | à faire |
| 5 | **Serveur multimédia DLNA/UPnP** | Go (lecture des vidéos/musique du disque par la TV) | à faire (code externe) |
| 6 | Cible de sauvegarde restic par HTTP | `rest-server` (Go), moins gourmand que Samba | à faire (code externe) |
| 7 | rsync | binaire fourni par TimeCapsuleSMB (démon désactivé par défaut) | possible |
| 8 | Comptes et partages multiples | Samba est en compte unique (root) chez TimeCapsuleSMB : à proposer en amont | à discuter |

Contraintes : 256 Mo de RAM (+ 256 Mo de swap), 1 cœur à 1 GHz → services en Go, légers, lancés au démarrage
par `demarrage.sh` ; tout reste réversible (fichiers sur le disque, rien dans le système d'Apple).
