# Go sur le NetBSD 6 de la Time Capsule : état du portage (29/10/2026)

Correctif : `analyse/go-netbsd6-timecapsule.patch` (Go 1.27.3), appliqué par `outils/construire-tc.sh`.

## Corrigé (V)

| Problème | Symptôme | Correction |
|---|---|---|
| `ucontext` : `uc_mcontext` à l'octet 36 (pas de remplissage EABI de NetBSD 7+) | `_lwp_create` → `EINVAL`, aucun thread | registres écrits aux positions du noyau, CPSR = mode utilisateur ; structure `ucontextt` sans remplissage |
| `___lwp_park60` (n° 478) absent | `SIGSYS` | `___lwp_park50` (n° 434), échéance absolue sur l'horloge réelle |
| appels système post-NetBSD 6 (`wait6` n° 481…) | `SIGSYS` fatal (ex. `os/exec`) | `SIGSYS` laissé passer : le noyau renvoie `ENOSYS` et la bibliothèque standard utilise ses replis |

Validé sur l'appareil : goroutines, préemption asynchrone, ramasse-miettes, aléa, réseau TCP/UDP, `os/exec`,
`strconv`, `sync/atomic` (suites officielles PASS) ; `wg-tc`, `tc-swap`, ReLive (200 requêtes sans erreur).

## Résolu : ce n'était pas Go, mais l'exécution depuis le disque HFS+ (V)

Symptômes observés d'abord : dans les gros binaires, valeurs lues nulles (`reflect` `TestSet` « <zero Value> »,
`math` `TestPow` avec `-Inf` lu `0`, `text/template` « nil pointer evaluating »), Tailscale qui s'arrête sur
`forcegc: phase error`. Les petits programmes, eux, marchaient.

Démarche (chaque piste écartée par un test sur l'appareil) : flottant matériel (`GOARM=5` : même échec),
ramasse-miettes (`GOGC=off`), préemption (`asyncpreemptoff=1`), transfert (SHA-256 identiques), taille du `.bss`
(40 Mo : OK), taille des constantes (5 Mo : OK), emplacement du segment de données (OK), swap (aucune page
relue depuis le swap), initialisation des paquets (`inittrace` : elle s'exécute). Indice décisif : dans le binaire
de test, le tableau `vfpowSC` contient les nombres finis (données statiques) mais pas les `-Inf`, que le code
d'initialisation devait écrire : ces écritures n'avaient pas eu lieu.

**Preuve** : le même binaire **échoue lancé depuis le disque HFS+** (`/Volumes/dk2`) et **réussit lancé depuis
un tmpfs**. Le pilote HFS+ du noyau rend des pages fausses lorsqu'il projette un gros exécutable en mémoire
(chargement à la demande) ; une page de code remplie de zéros devient une suite d'instructions sans effet
(`0x00000000` = `andeq r0, r0, r0` sur ARM). La lecture ordinaire du fichier est juste (d'où des SHA-256
identiques). C'est sans doute pour cela que TimeCapsuleSMB copie `smbd` en RAM avant de le lancer.

Validation depuis un tmpfs : suites officielles `reflect`, `math`, `strconv`, `sync/atomic`,
`internal/poly1305`, `chacha20poly1305` : PASS ; `text/template` et `html/template` : PASS sauf les tests qui
lisent `testdata/` (fichiers absents de l'appareil).

**Règle** : ne jamais exécuter un programme depuis le disque HFS+. `demarrage.sh` copie les binaires dans un
tmpfs (`/mnt/seconde-vie`, 24 Mo) et les lance depuis là.
