# Tests du partage SMB 3 (29/10/2026, après installation de TimeCapsuleSMB)

Fichier aléatoire de 200 Mo écrit dans un dossier de test, relu, comparé (md5), puis supprimé.

## Depuis serveur-maison (Debian 12, smbclient 4.17, Ethernet)

| Protection SMB 3 (`--client-protection`) | Écriture | Lecture | Intégrité |
|---|---|---|---|
| aucune (`off`) | 25,4 Mo/s | 28,5 Mo/s | OK |
| signature (`sign`) | 13,5 Mo/s | 14,4 Mo/s | OK |
| chiffrement (`encrypt`) | 6,4 Mo/s | 6,0 Mo/s | OK |

Le processeur ARM à 1 GHz de la Time Capsule chiffre et signe en logiciel : c'est lui qui limite le débit.

## Depuis le Mac (macOS 27, Wi-Fi 6 vers le routeur OpenWrt, Time Capsule en Ethernet)

- `mount_smbfs` : **SMB 3.1.1** négocié ; algorithmes AES-128/256 CCM/GCM proposés ; macOS ne chiffre pas par
  défaut sur le réseau local (`SMB_CURR_ENCRYPT_ALGORITHM OFF`).
- 200 Mo : écriture 10 s (≈ 20 Mo/s), lecture 7 s (≈ 28 Mo/s), intégrité OK.

## État de l'appareil lu par ACP (base de la supervision)

- Disque `wd0` 2 To, volume `Data` (HFS) : 751 Go utilisés, **1,15 To libres**.
- Capteurs `sySI` : ventilateur 1765 tr/min (57 %), températures internes 43–49 °C ; `T_hdd` renvoie 0 (capteur
  du disque non remonté).
- `sySt` : aucun problème signalé.

## Points à décider

- **Niveau de protection** pour les copies depuis serveur-maison : signature (14 Mo/s) = bon compromis sur le réseau
  local ; chiffrement (6 Mo/s) seulement si nécessaire.
- **Time Machine du Mac actuel** : le Mac occupe ≈ 1,9 To (hors copie de l'ancienne sauvegarde), la Time Capsule
  n'a que 1,15 To libres → sauvegarde complète impossible sans exclusions (Photos, Nextcloud déjà synchronisé…)
  ou sans supprimer l'ancienne sauvegarde du MacBook Pro (dont une copie existe sur le Mac).
