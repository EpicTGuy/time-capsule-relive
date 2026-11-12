# Revue de sécurité — 12/11/2026

Avant la première publication du dépôt. Portée : outils installés sur la Time Capsule (ReLive, tc-pont, tc-dhcp,
relais.sh, demarrage.sh), outils du Mac, export public.

## Modèle de menace

| Qui | Ce qu'il peut tenter | Protection |
|---|---|---|
| Un appareil du Wi-Fi de la Time Capsule ou de son câble | joindre la Time Capsule, les autres appareils, Internet | comme une box : services de la Time Capsule protégés par son mot de passe ; aucun accès au réseau de la box sauf par les connexions qu'il ouvre lui-même |
| Un appareil du réseau Wi-Fi rejoint (box, partage de connexion, Wi-Fi public) | joindre les services de la Time Capsule relayés par tc-pont (SSH, SMB, ReLive, ACP : ports 22, 80, 139, 443, 445, 5009) | mot de passe de la Time Capsule ; **voir point 3** |
| Un appareil du réseau Wi-Fi rejoint | joindre les appareils partagés derrière la Time Capsule | traduction d'adresses : seules passent les réponses aux connexions ouvertes de l'intérieur |
| Un utilisateur du partage SMB | lire les mots de passe gardés par le mode automatique | fichier hors du partage (voir point 1) |
| Une page web malveillante ouverte sur le Mac | agir sur ReLive à la place de l'utilisateur | jeton CSRF sur chaque formulaire, cookie `HttpOnly`, `SameSite=Strict`, `Secure` en HTTPS |
| Quelqu'un qui devine le mot de passe | essais en série sur ReLive | pause d'une seconde après chaque échec |

## Constats

1. **Mots de passe du mode automatique** (`mode-auto.json` : mot de passe d'administration, clés des réseaux
   connus). Sur le disque, dans `.seconde-vie/`, hors de `ShareRoot` (seul dossier partagé en SMB). Les droits
   600 ne sont pas appliqués (volume HFS+ monté sans propriétaires) : le fichier n'est lisible qu'en SSH root,
   qui a de toute façon tous les droits. Effacé du fichier quand on désactive le mode automatique.
   ReLive ne renvoie jamais ces valeurs aux pages (effacées avant l'affichage, vérifié à la lecture du code).
2. **ReLive** : session obligatoire, jeton CSRF, cookie protégé, HTTPS (certificat auto-signé). La pause après un
   échec freine les essais en série, pas les essais en parallèle.
3. **Services exposés sur un Wi-Fi étranger.** Quand la Time Capsule rejoint un réseau qu'on ne contrôle pas
   (Wi-Fi public, hôtel), ses services d'administration y sont joignables par tous les appareils de ce réseau,
   derrière son seul mot de passe ; le SSH d'Apple n'accepte que d'anciens algorithmes. **Corrigé** (12/11/2026) :
   tc-pont ne relaie ces services, ni Bonjour, que sur les réseaux marqués « de confiance » dans ReLive
   (`reseaux-confiance.txt`) ; ailleurs, on administre par le Wi-Fi de la Time Capsule ou par le câble. Testé par
   test unitaire (liste, valeurs piégées) ; pas encore en conditions réelles sur un réseau non marqué.
4. **Traduction d'adresses** : pas de redirection de ports ; un flux n'existe que s'il a été ouvert de
   l'intérieur ; les ports de traduction (32768–65535) sont séparés de ceux de la Time Capsule.
5. **Câble** : tc-pont ne sert d'adresses sur le câble que si aucun serveur DHCP n'y répond (deux sondes), pour
   ne jamais perturber un réseau existant ; seule une réponse venue du câble compte.

## Secrets et données personnelles

- Aucun mot de passe, clé ou jeton dans le dépôt ; sauvegardes de configuration et binaires hors du dépôt
  (`.gitignore`).
- Export public : `prive/exporter-public.sh` anonymise (règles `prive/anonymisation.sed`) puis refuse d'exporter
  s'il reste un motif interdit ; l'export n'a pas d'historique git.
- Les commandes d'inspection de la Time Capsule masquent les clés avant affichage.

## Chaîne d'approvisionnement

- Go officiel téléchargé et contrôlé par somme SHA-256, puis corrigé par nos correctifs (dans le dépôt).
- Dépendances Go figées par `go.sum` (gVisor, wireguard-go) ; ReLive, tc-dhcp et tc-swap n'utilisent que la
  bibliothèque standard.
- Aucun logiciel d'Apple n'est distribué ; nos binaires ne sont pas dans le dépôt (construits par
  `outils/construire-tc.sh`).
