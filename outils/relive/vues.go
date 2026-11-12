package main

// Rendu HTML direct, sans moteur de gabarits : binaire plus petit et moins de
// mémoire sur un appareil qui en a peu. Tout texte variable passe par e()
// (échappement HTML).

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func e(s string) string { return html.EscapeString(s) }

func chaine(d map[string]any, cle string) string {
	s, _ := d[cle].(string)
	return s
}

func afficher(w http.ResponseWriter, nom string, d map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:")
	w.Header().Set("X-Frame-Options", "DENY")
	var b strings.Builder
	switch nom {
	case "connexion.html":
		vueConnexion(&b, d)
	case "redemarrage.html":
		vueRedemarrage(&b, d)
	default:
		debut(&b, d)
		switch nom {
		case "tableau.html":
			vueTableau(&b, d)
		case "wifi.html":
			vueWiFi(&b, d)
		case "journaux.html":
			vueJournaux(&b, d)
		case "systeme.html":
			vueSysteme(&b, d)
		default:
			log.Printf("vue inconnue %s", nom)
		}
		b.WriteString("</main></div></body></html>")
	}
	w.Write([]byte(b.String()))
}

const tete = `<!doctype html><html lang="fr"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<link rel="stylesheet" href="/static/style.css">`

const marque = `<div class="marque"><span class="logo">◷</span><div><strong>ReLive</strong>` +
	`<small>When Apple leaves,<br>Time Capsule relives</small></div></div>`

func champCSRF(d map[string]any) string {
	return `<input type="hidden" name="csrf" value="` + e(chaine(d, "CSRF")) + `">`
}

func debut(b *strings.Builder, d map[string]any) {
	b.WriteString(tete + "<title>ReLive — Time Capsule</title></head><body><div class=\"appli\"><nav class=\"menu\">" + marque)
	page := chaine(d, "Page")
	for _, l := range [][3]string{{"/", "tableau", "Tableau de bord"}, {"/wifi", "wifi", "Wi-Fi"},
		{"/journaux", "journaux", "Journaux"}, {"/systeme", "systeme", "Système"}} {
		classe := ""
		if l[1] == page {
			classe = ` class="actif"`
		}
		b.WriteString(`<a href="` + l[0] + `"` + classe + `>` + l[2] + `</a>`)
	}
	b.WriteString(`<form method="post" action="/deconnexion" class="sortie">` + champCSRF(d) +
		`<button>Se déconnecter</button></form></nav><main>`)
	if err := chaine(d, "Erreur"); err != "" {
		b.WriteString(`<p class="alerte">` + e(err) + `</p>`)
	}
}

func vueConnexion(b *strings.Builder, d map[string]any) {
	b.WriteString(tete + `<title>ReLive — connexion</title></head><body class="accueil"><form method="post" class="carte connexion">` +
		marque + `<label>Mot de passe de la Time Capsule<input type="password" name="motdepasse" autofocus required></label>`)
	if err := chaine(d, "Erreur"); err != "" {
		b.WriteString(`<p class="alerte">` + e(err) + `</p>`)
	}
	b.WriteString(`<button>Se connecter</button><p class="discret">Vérifié par la Time Capsule elle-même ; ` +
		`il n'est enregistré nulle part.</p></form></body></html>`)
}

func vueRedemarrage(b *strings.Builder, d map[string]any) {
	b.WriteString(tete + `<meta http-equiv="refresh" content="120;url=/"><title>ReLive — redémarrage</title></head>` +
		`<body class="accueil"><div class="carte connexion"><h1>Redémarrage en cours…</h1><p>` + e(chaine(d, "Raison")) +
		`</p><p class="discret">La page se rechargera d'elle-même dans 2 minutes.</p></div></body></html>`)
}

func ligne(b *strings.Builder, nom, valeur, classe string) {
	b.WriteString(`<li><span>` + e(nom) + `</span><b class="` + classe + `">` + e(valeur) + `</b></li>`)
}

func vueTableau(b *strings.Builder, d map[string]any) {
	b.WriteString(`<h1>` + e(chaine(d, "Nom")) + `</h1><p class="discret">` + e(chaine(d, "Modele")) + ` · logiciel ` +
		e(chaine(d, "Version")) + ` · ` + e(chaine(d, "IP")) + ` · allumée depuis ` + e(chaine(d, "Allumee")) + `</p>`)
	if pb, _ := d["Problemes"].([]string); len(pb) > 0 {
		b.WriteString(`<p class="alerte">La Time Capsule signale : « ` + e(strings.Join(pb, " », « ")) + ` »</p>`)
	}
	b.WriteString(`<div class="grille">`)

	dq, _ := d["Disque"].(Disque)
	rouge := ""
	if dq.Pourcent >= 90 {
		rouge = " rouge"
	}
	fmt.Fprintf(b, `<section class="carte"><h2>Disque</h2><p class="grand">%.0f Go <small>libres sur %.0f</small></p>`+
		`<progress class="jauge%s" max="100" value="%d"></progress><p class="discret">%d %% utilisés</p></section>`,
		dq.LibreGo, dq.TailleGo, rouge, dq.Pourcent, dq.Pourcent)

	sm, _ := d["SMART"].(SMART)
	b.WriteString(`<section class="carte"><h2>Santé du disque (SMART)</h2>`)
	if sm.Present {
		etat, classe := "Sain", "vert"
		if !sm.Sain {
			etat, classe = "À surveiller", "rouge"
		}
		fmt.Fprintf(b, `<p class="grand %s">%s</p><p>%d °C · %d h de fonctionnement</p><p class="discret">relevé du %s</p>`,
			classe, etat, sm.Temperature, sm.Heures, sm.Date.Format("02/01 15:04"))
	} else {
		b.WriteString(`<p class="discret">Pas encore de relevé.</p>`)
	}
	b.WriteString(`</section>`)

	b.WriteString(`<section class="carte"><h2>Températures</h2><ul class="valeurs">`)
	if cs, _ := d["Capteurs"].([]map[string]any); cs != nil {
		for _, c := range cs {
			nom, _ := c["Nom"].(string)
			val, _ := c["Valeur"].(int64)
			chaud, _ := c["Chaud"].(bool)
			classe := ""
			if chaud {
				classe = "rouge"
			}
			ligne(b, nom, strconv.FormatInt(val, 10)+" °C", classe)
		}
	}
	if v, ok := d["Ventilateur"].(int64); ok {
		ligne(b, "Ventilateur", strconv.FormatInt(v, 10)+" tr/min", "")
	}
	b.WriteString(`</ul></section>`)

	m, _ := d["Memoire"].(Memoire)
	fmt.Fprintf(b, `<section class="carte"><h2>Mémoire</h2><p class="grand">%d Mo <small>libres sur %d</small></p>`+
		`<p>Swap : %d / %d Mo</p></section>`, m.LibreMo, m.TotalMo, m.SwapUtiliseMo, m.SwapMo)

	p, _ := d["Processus"].(Processus)
	b.WriteString(`<section class="carte"><h2>Services</h2><ul class="valeurs">`)
	if p.SambaNb > 0 {
		ligne(b, "Partage SMB 3 (Samba)", fmt.Sprintf("actif · %d processus", p.SambaNb), "vert")
	} else {
		ligne(b, "Partage SMB 3 (Samba)", "arrêté", "rouge")
	}
	ligne(b, "WireGuard (wg-tc)", map[bool]string{true: "actif", false: "non utilisé"}[p.WireGuard], "")
	ligne(b, "Tailscale", map[bool]string{true: "actif", false: "non utilisé"}[p.Tailscale], "")
	b.WriteString(`</ul></section>`)

	b.WriteString(`<section class="carte"><h2>Sauvegardes reçues</h2>`)
	if s := chaine(d, "DerniereSauvegarde"); s != "" {
		b.WriteString(`<p>Dépôt restic (Immich) : dernière sauvegarde le <b>` + e(s) + `</b></p>`)
	} else {
		b.WriteString(`<p class="discret">Aucun dépôt de sauvegarde détecté.</p>`)
	}
	b.WriteString(`</section></div>`)

	if sm.Present {
		b.WriteString(`<details class="carte"><summary>Détail SMART</summary><table><tr><th>ID</th><th>Attribut</th>` +
			`<th>Valeur</th><th>Seuil</th><th>Brut</th></tr>`)
		for _, a := range sm.Attributs {
			classe := ""
			if a.Alarme {
				classe = ` class="rouge"`
			}
			fmt.Fprintf(b, `<tr%s><td>%d</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td></tr>`,
				classe, a.ID, e(a.Nom), a.Valeur, a.Seuil, a.Brut)
		}
		b.WriteString(`</table></details>`)
	}
}

var canaux24 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
var canaux5 = []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}

// Les listes déroulantes ne sont jamais dans leur <label> : sous Chromium (Arc…), le clic transmis par
// l'étiquette rouvre/referme aussitôt la liste, qui semble ne pas s'ouvrir.
func vueWiFi(b *strings.Builder, d map[string]any) {
	b.WriteString(`<h1>Wi-Fi</h1><p class="discret">Chaque modification sauvegarde d'abord la configuration actuelle, ` +
		`puis redémarre la Time Capsule (1 à 2 minutes).</p>`)
	if m := chaine(d, "Message"); m != "" {
		b.WriteString(`<p class="carte">` + e(m) + `</p>`)
	}
	b.WriteString(`<div class="grille">`)
	rs, _ := d["Radios"].([]Radio)
	for _, r := range rs {
		details := r.Role + " · " + r.Securite + " · " + r.MAC
		if r.Invite {
			details += " · réseau invité actif"
		}
		fmt.Fprintf(b, `<form method="post" action="/wifi/modifier" class="carte">%s<input type="hidden" name="radio" value="%d">`+
			`<h2>Radio %s</h2><p class="discret">%s</p>`, champCSRF(d), r.Index, e(r.Bande), e(details))
		b.WriteString(`<label>Nom du réseau<input name="ssid" maxlength="32" value="` + e(r.SSID) + `"></label>` +
			`<label>Nouveau mot de passe Wi-Fi <small>(vide = inchangé)</small><input type="password" name="cle" ` +
			`minlength="8" maxlength="63" autocomplete="new-password"></label>`)
		fmt.Fprintf(b, `<label for="canal%d">Canal</label><select id="canal%d" name="canal">`, r.Index, r.Index)
		sel := ""
		if r.CanalAuto {
			sel = " selected"
		}
		fmt.Fprintf(b, `<option value="auto"%s>Automatique (actuel : %d)</option>`, sel, r.Canal)
		liste := canaux24
		if r.Bande == "5 GHz" {
			liste = canaux5
		}
		for _, c := range liste {
			sel = ""
			if !r.CanalAuto && int64(c) == r.Canal {
				sel = " selected"
			}
			fmt.Fprintf(b, `<option value="%d"%s>%d</option>`, c, sel, c)
		}
		coche := ""
		if r.Masque {
			coche = " checked"
		}
		b.WriteString(`</select><label class="case"><input type="checkbox" name="masque"` + coche +
			`> Réseau masqué</label><button>Appliquer et redémarrer</button></form>`)
	}
	b.WriteString(`</div>`)
	vueAuto(b, d)
	vueRejoindre(b, d)
	b.WriteString(`<section class="carte"><h2>Configurations sauvegardées</h2>`)
	if cp, _ := d["Copies"].([]string); len(cp) > 0 {
		b.WriteString(`<form method="post" action="/wifi/restaurer">` + champCSRF(d) + `<select name="copie">`)
		for _, c := range cp {
			b.WriteString(`<option>` + e(c) + `</option>`)
		}
		b.WriteString(`</select> <button>Restaurer et redémarrer</button></form>`)
	} else {
		b.WriteString(`<p class="discret">Aucune pour l'instant : la première sera créée à la première modification.</p>`)
	}
	b.WriteString(`</section>`)
}

func vueJournaux(b *strings.Builder, d map[string]any) {
	b.WriteString(`<h1>Journaux</h1><section class="carte"><h2>Time Capsule (plus récents en premier)</h2><pre>`)
	if ls, _ := d["Lignes"].([]string); ls != nil {
		for _, l := range ls {
			b.WriteString(e(l) + "\n")
		}
	}
	b.WriteString(`</pre></section>`)
	if s := chaine(d, "SecondeVie"); s != "" {
		b.WriteString(`<section class="carte"><h2>Seconde vie (démarrage)</h2><pre>` + e(s) + `</pre></section>`)
	}
}

func vueSysteme(b *strings.Builder, d map[string]any) {
	m, _ := d["Memoire"].(Memoire)
	p, _ := d["Processus"].(Processus)
	fmt.Fprintf(b, `<h1>Système</h1><div class="grille"><section class="carte"><h2>Logiciel</h2><p>%s</p>`+
		`<p class="discret">ReLive · projet « Time Capsule ReLive » (GPL-3.0)</p></section>`+
		`<section class="carte"><h2>Mémoire</h2><p>%d Mo libres sur %d · swap %d/%d Mo</p><p>Samba : %d processus, %d Mo</p></section>`,
		e(chaine(d, "Noyau")), m.LibreMo, m.TotalMo, m.SwapUtiliseMo, m.SwapMo, p.SambaNb, p.SambaMo)
	b.WriteString(`<form method="post" action="/systeme/redemarrer" class="carte">` + champCSRF(d) +
		`<h2>Redémarrer</h2><p class="discret">Coupe le Wi-Fi et le partage 1 à 2 minutes.</p>` +
		`<button class="danger">Redémarrer la Time Capsule</button></form></div>`)
}

// vueRejoindre : faire rejoindre à une radio une box, un routeur ou un partage de connexion.
func vueRejoindre(b *strings.Builder, d map[string]any) {
	b.WriteString(`<form method="post" action="/wifi/rejoindre" class="carte">` + champCSRF(d) +
		`<h2>Rejoindre un réseau Wi-Fi</h2><p class="discret">Une radio rejoint le réseau choisi (box, routeur, ` +
		`partage de connexion d'un téléphone) ; l'autre garde le Wi-Fi de la Time Capsule, qui reste joignable ` +
		`par ce réseau et, sans câble Ethernet, partage la connexion. Le 5 GHz est plus rapide, le 2,4 GHz porte ` +
		`plus loin (partage d'iPhone : activer « Maximiser la compatibilité » pour le 2,4 GHz).</p>`)
	rs, _ := d["Reseaux"].([]Reseau)
	if len(rs) == 0 {
		b.WriteString(`<p class="discret">Aucun réseau dans le dernier scan : <a href="/wifi">actualiser</a>.</p>`)
	} else {
		b.WriteString(`<label for="reseau">Réseau vu par la Time Capsule</label><select id="reseau" name="reseau"><option value="">— choisir —</option>`)
		for _, r := range rs {
			dis, bande := "", "2,4 GHz"
			if !r.Possible {
				dis = " disabled"
			}
			if r.Radio == 0 {
				bande = "5 GHz"
			}
			fmt.Fprintf(b, `<option value="%d|%d|%s"%s>%s — %s, canal %d, %d dBm, %s</option>`,
				r.Radio, r.Canal, e(r.SSID), dis, e(r.SSID), bande, r.Canal, r.Signal, e(r.Securite))
		}
		b.WriteString(`</select>`)
	}
	b.WriteString(`<label>…ou nom d'un réseau masqué<input name="autre" maxlength="32"></label>` +
		`<label for="bande">Bande du réseau masqué</label><select id="bande" name="radio">` +
		`<option value="1">2,4 GHz</option><option value="0">5 GHz</option></select>` +
		`<label>Mot de passe du réseau <small>(vide si ouvert)</small><input type="password" name="cle" ` +
		`minlength="8" maxlength="63" autocomplete="off"></label>` +
		`<label><input type="checkbox" name="confiance" value="1"> Réseau de confiance <small>(la Time Capsule y ` +
		`reste administrable : SSH, ReLive, partage de fichiers ; à laisser décoché pour un Wi-Fi public ou d'hôtel)` +
		`</small></label>` +
		`<button>Rejoindre et redémarrer</button><p class="discret">La configuration actuelle est sauvegardée ` +
		`d'abord : « Restaurer » ci-dessous permet de revenir en arrière.</p></form>`)
}

// vueAuto : mode automatique (câble vers un réseau : deux radios en Wi-Fi ; sinon client d'un réseau connu).
func vueAuto(b *strings.Builder, d map[string]any) {
	m, _ := d["Auto"].(ModeAuto)
	etat := "inactif"
	if m.Actif {
		etat = "actif"
	}
	if c := chaine(d, "Cable"); c != "" {
		etat += " · câble Ethernet " + c
	}
	b.WriteString(`<section class="carte"><h2>Mode automatique</h2><p class="discret">Câble Ethernet vers une box ou un ` +
		`réseau : les deux radios sont le Wi-Fi de la Time Capsule. Câble débranché, ou vers un routeur branché par ` +
		`son port WAN : elle rejoint le réseau connu le mieux reçu (le 5 GHz est préféré s'il capte presque aussi ` +
		`bien) et partage sa connexion sur son Wi-Fi et sur le câble. Chaque bascule redémarre la Time Capsule ` +
		`(environ 1 minute).</p><p><b>` + e(etat) + `</b></p>`)
	if len(m.Reseaux) == 0 {
		b.WriteString(`<p class="discret">Aucun réseau connu : ajoutez-en ci-dessous (à signal égal, le premier passe avant).</p>`)
	} else {
		b.WriteString(`<table>`)
		for i, c := range m.Reseaux {
			bande := "2,4 GHz"
			if c.Radio == 0 {
				bande = "5 GHz"
			}
			confiance, bascule := "non", "Marquer de confiance"
			if m.deConfiance(c.SSID) {
				confiance, bascule = "de confiance", "Retirer la confiance"
			}
			fmt.Fprintf(b, `<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td><form method="post" action="/auto/liste">%s`+
				`<input type="hidden" name="i" value="%d"><button name="action" value="monter">↑</button> `+
				`<button name="action" value="confiance">%s</button> `+
				`<button name="action" value="retirer" class="danger">Retirer</button></form></td></tr>`,
				i+1, e(c.SSID), bande, confiance, champCSRF(d), i, bascule)
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`<form method="post" action="/auto/ajouter">` + champCSRF(d))
	if rs, _ := d["Reseaux"].([]Reseau); len(rs) > 0 {
		b.WriteString(`<label for="auto-reseau">Ajouter un réseau vu</label><select id="auto-reseau" name="reseau">` +
			`<option value="">— choisir —</option>`)
		for _, r := range rs {
			if !r.Possible {
				continue
			}
			bande := "2,4 GHz"
			if r.Radio == 0 {
				bande = "5 GHz"
			}
			fmt.Fprintf(b, `<option value="%d|%d|%s">%s — %s</option>`, r.Radio, r.Canal, e(r.SSID), e(r.SSID), bande)
		}
		b.WriteString(`</select>`)
	}
	b.WriteString(`<label>…ou nom d'un réseau (masqué, partage de téléphone…)<input name="autre" maxlength="32"></label>` +
		`<label for="auto-bande">Bande de ce réseau</label><select id="auto-bande" name="radio"><option value="1">2,4 GHz` +
		`</option><option value="0">5 GHz</option></select><label>Mot de passe du réseau <small>(vide si ouvert)` +
		`</small><input type="password" name="cle" minlength="8" maxlength="63" autocomplete="off"></label>` +
		`<label><input type="checkbox" name="confiance" value="1"> Réseau de confiance <small>(la Time Capsule y ` +
		`reste administrable : SSH, ReLive, partage de fichiers ; à laisser décoché pour un Wi-Fi public ou d'hôtel)` +
		`</small></label>` +
		`<button>Ajouter aux réseaux connus</button></form>`)
	if m.Actif {
		b.WriteString(`<form method="post" action="/auto/desactiver">` + champCSRF(d) +
			`<button class="danger">Désactiver le mode automatique</button></form>`)
	} else {
		b.WriteString(`<form method="post" action="/auto/activer">` + champCSRF(d) + `<p class="discret">À l'activation, ` +
			`la configuration actuelle (les deux radios en Wi-Fi) devient la configuration de base, et le mot de passe ` +
			`d'administration est gardé sur la Time Capsule (fichier protégé) pour basculer sans vous.</p>` +
			`<button>Activer le mode automatique</button></form>`)
	}
	b.WriteString(`</section>`)
}
