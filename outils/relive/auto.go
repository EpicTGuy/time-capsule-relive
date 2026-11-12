package main

// Mode automatique. Câble Ethernet vers un réseau (box, routeur par un port LAN) : les deux radios sont le Wi-Fi
// de la Time Capsule (configuration de base, mémorisée à l'activation), pont simple vers le réseau du câble comme
// Apple l'a prévu. Câble débranché, ou vers un appareil qui attend une adresse (routeur branché par son port
// WAN) : une radio rejoint le meilleur réseau connu visible, l'autre garde le Wi-Fi de la Time Capsule, et
// tc-pont partage la connexion sur ce Wi-Fi et sur le câble (outils/tc/relais.sh). Câble de nouveau vers un
// réseau : retour à la configuration de base.
//
// Le firmware ne change pas le rôle d'une radio à chaud : chaque bascule réécrit la configuration Wi-Fi puis
// redémarre la Time Capsule (environ 1 minute de coupure). L'état du câble est noté par relais.sh dans
// /tmp/relais/cable (surveillance de demarrage.sh, toutes les 30 s) : 0 rien, 1 réseau, 2 appareil en attente.
//
// Le fichier mode-auto.json (droits 600, dossier de travail) garde le mot de passe d'administration — il faut
// pouvoir réécrire la configuration sans personne — et ceux des réseaux connus ; ReLive ne les affiche jamais.
//
// Réseaux de confiance : seuls sur eux, la Time Capsule reste administrable depuis le réseau rejoint (SSH, ReLive,
// partage de fichiers, ACP, Bonjour relayés par tc-pont). Sur un Wi-Fi d'hôtel ou public, rien de cela n'est
// exposé ; on l'administre alors par son propre Wi-Fi ou par le câble. Liste lue par relais.sh dans
// reseaux-confiance.txt (un nom par ligne), réécrite à chaque modification.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ReseauConnu struct {
	SSID  string
	Cle   string `json:",omitempty"`
	Radio int    // 0 = 5 GHz, 1 = 2,4 GHz
}

type ModeAuto struct {
	Actif     bool
	Mdp       string `json:",omitempty"`
	Base      []byte `json:",omitempty"` // configuration Wi-Fi « deux radios en point d'accès » (CFB brut)
	Reseaux   []ReseauConnu
	Confiance []string `json:",omitempty"` // noms des réseaux de confiance
}

func (m ModeAuto) deConfiance(ssid string) bool {
	for _, c := range m.Confiance {
		if c == ssid {
			return true
		}
	}
	return false
}

func (m *ModeAuto) definirConfiance(ssid string, oui bool) {
	var garde []string
	for _, c := range m.Confiance {
		if c != ssid {
			garde = append(garde, c)
		}
	}
	if oui {
		garde = append(garde, ssid)
	}
	m.Confiance = garde
}

func fichierAuto() string { return filepath.Join(dossier, "mode-auto.json") }

func lireAuto() ModeAuto {
	var m ModeAuto
	if b, err := os.ReadFile(fichierAuto()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func ecrireAuto(m ModeAuto) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := ecrireAtomique(fichierAuto(), b, 0o600); err != nil {
		return err
	}
	var liste []byte
	for _, c := range m.Confiance {
		liste = append(append(liste, c...), '\n')
	}
	return ecrireAtomique(filepath.Join(dossier, "reseaux-confiance.txt"), liste, 0o600)
}

func ecrireAtomique(chemin string, b []byte, droits os.FileMode) error {
	tmp := chemin + ".n"
	if err := os.WriteFile(tmp, b, droits); err != nil {
		return err
	}
	return os.Rename(tmp, chemin)
}

// etatCable : (le câble mène à un réseau, état connu). Inconnu si relais.sh ne l'a pas noté depuis 2 minutes.
func etatCable() (bool, bool) {
	c := codeCable()
	return c == "1", c != ""
}

// codeCable : « 0 », « 1 », « 2 » (voir plus haut), vide si inconnu.
func codeCable() string {
	fi, err := os.Stat("/tmp/relais/cable")
	if err != nil || time.Since(fi.ModTime()) > 2*time.Minute {
		return ""
	}
	b, _ := os.ReadFile("/tmp/relais/cable")
	return strings.TrimSpace(string(b))
}

// radioCliente : indice de la radio en client Wi-Fi, -1 si les deux sont points d'accès.
func radioCliente(conf Dict) int {
	lst, _ := conf.Get("radios").([]any)
	for i, x := range lst {
		if st, _ := x.(Dict).Get("raSt").(int64); st == 1 {
			return i
		}
	}
	return -1
}

// automate : décide toutes les 20 s ; un état doit être constaté 3 fois de suite (1 minute) avant d'agir, et
// rien n'est fait pendant 3 minutes après le démarrage (ACPd, scan Wi-Fi, première mesure du câble).
func automate() {
	time.Sleep(3 * time.Minute)
	var dernier string
	vu := 0
	aucunSignale := false
	for ; ; time.Sleep(20 * time.Second) {
		m := lireAuto()
		cable, connu := etatCable()
		if !m.Actif || !connu || len(m.Base) == 0 {
			vu = 0
			continue
		}
		_, conf, err := lireWiFi(m.Mdp)
		if err != nil {
			log.Printf("mode automatique : lecture Wi-Fi : %v", err)
			continue
		}
		client := radioCliente(conf)
		etat := strconv.FormatBool(cable) + strconv.Itoa(client)
		if etat != dernier {
			dernier, vu = etat, 0
		}
		if vu++; vu < 3 {
			continue
		}
		switch {
		case cable && client >= 0:
			log.Printf("mode automatique : câble branché, retour aux deux radios en Wi-Fi")
			basculer(m.Mdp, m.Base)
		case !cable && client < 0:
			nouvelle, nom, err := choisirReseau(m)
			if err != nil {
				if !aucunSignale {
					log.Printf("mode automatique : câble débranché, %v", err)
					aucunSignale = true
				}
				continue
			}
			aucunSignale = false
			log.Printf("mode automatique : câble débranché, la Time Capsule rejoint « %s »", nom)
			basculer(m.Mdp, EcrireCFB(nouvelle))
		}
	}
}

// basculer écrit la configuration (copie de l'actuelle d'abord) et redémarre ; puis laisse le temps de revenir.
func basculer(mdp string, cfb []byte) {
	if p, err := acp.Lire(mdp, "WiFi"); err == nil {
		sauvegarderWiFi(p["WiFi"])
	}
	if err := acp.Ecrire(mdp, "WiFi", cfb); err != nil {
		log.Printf("mode automatique : écriture refusée : %v", err)
		return
	}
	acp.Redemarrer(mdp)
	time.Sleep(5 * time.Minute) // le redémarrage interrompt ReLive avant, en principe
}

// bonus5GHz : à signal égal, le 5 GHz est bien plus rapide (canaux plus larges, moins encombrés) ; il porte
// moins loin, d'où un bonus et non une priorité absolue : un 5 GHz plus faible de plus de 10 dB perd.
const bonus5GHz = 10

// choisirReseau : réseau connu le mieux reçu au dernier scan (signal + bonus 5 GHz) ; à égalité, le premier de
// la liste.
func choisirReseau(m ModeAuto) (Dict, string, error) {
	vus, err := reseauxVus(m.Mdp)
	if err != nil {
		return nil, "", err
	}
	o, err := LireCFB(m.Base)
	if err != nil {
		return nil, "", err
	}
	base, _ := o.(Dict)
	c, v, ok := meilleurReseau(m.Reseaux, vus)
	if !ok {
		return nil, "", errors.New("aucun réseau connu en vue")
	}
	conf, err := configClient(base, c.Radio, c.SSID, c.Cle, v.Canal)
	return conf, c.SSID, err
}

func meilleurReseau(connus []ReseauConnu, vus []Reseau) (ReseauConnu, Reseau, bool) {
	var mc ReseauConnu
	var mv Reseau
	trouve := false
	score := func(v Reseau) int64 {
		if v.Radio == 0 {
			return v.Signal + bonus5GHz
		}
		return v.Signal
	}
	for _, c := range connus {
		for _, v := range vus {
			if v.SSID == c.SSID && v.Radio == c.Radio && v.Possible && (!trouve || score(v) > score(mv)) {
				mc, mv, trouve = c, v, true
			}
		}
	}
	return mc, mv, trouve
}

// --- Pages ---

func autoActiver(w http.ResponseWriter, r *http.Request, s *session) {
	brut, conf, err := lireWiFi(s.mdp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if radioCliente(conf) >= 0 {
		http.Error(w, "une radio est cliente d'un réseau : restaurez d'abord la configuration « deux radios en Wi-Fi » "+
			"(Configurations sauvegardées), qui deviendra la configuration de base", http.StatusConflict)
		return
	}
	m := lireAuto()
	m.Actif, m.Mdp, m.Base = true, s.mdp, brut
	if err := ecrireAuto(m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/wifi?ok=Mode+automatique+activé", http.StatusSeeOther)
}

func autoDesactiver(w http.ResponseWriter, r *http.Request, s *session) {
	m := lireAuto()
	m.Actif, m.Mdp = false, "" // le mot de passe d'administration ne reste pas stocké
	ecrireAuto(m)
	http.Redirect(w, r, "/wifi?ok=Mode+automatique+désactivé", http.StatusSeeOther)
}

func autoAjouter(w http.ResponseWriter, r *http.Request, s *session) {
	radio, _ := strconv.Atoi(r.FormValue("radio"))
	ssid := strings.TrimSpace(r.FormValue("autre"))
	if ssid == "" {
		if parts := strings.SplitN(r.FormValue("reseau"), "|", 3); len(parts) == 3 {
			radio, _ = strconv.Atoi(parts[0])
			ssid = parts[2]
		}
	}
	cle := r.FormValue("cle")
	if ssid == "" || len(ssid) > 32 || (radio != 0 && radio != 1) || (cle != "" && (len(cle) < 8 || len(cle) > 63)) {
		http.Error(w, "réseau, bande ou mot de passe invalide (8 à 63 caractères, vide si ouvert)", http.StatusBadRequest)
		return
	}
	m := lireAuto()
	var garde []ReseauConnu
	for _, c := range m.Reseaux {
		if c.SSID != ssid || c.Radio != radio {
			garde = append(garde, c)
		}
	}
	m.Reseaux = append(garde, ReseauConnu{SSID: ssid, Cle: cle, Radio: radio})
	m.definirConfiance(ssid, r.FormValue("confiance") == "1")
	if err := ecrireAuto(m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/wifi?ok=Réseau+connu+ajouté", http.StatusSeeOther)
}

// autoListe : retirer un réseau connu, le monter d'un cran (à signal égal), ou changer sa confiance.
func autoListe(w http.ResponseWriter, r *http.Request, s *session) {
	i, err := strconv.Atoi(r.FormValue("i"))
	m := lireAuto()
	if err != nil || i < 0 || i >= len(m.Reseaux) {
		http.Error(w, "réseau inconnu", http.StatusBadRequest)
		return
	}
	switch r.FormValue("action") {
	case "retirer":
		m.Reseaux = append(m.Reseaux[:i], m.Reseaux[i+1:]...)
	case "monter":
		if i > 0 {
			m.Reseaux[i-1], m.Reseaux[i] = m.Reseaux[i], m.Reseaux[i-1]
		}
	case "confiance":
		m.definirConfiance(m.Reseaux[i].SSID, !m.deConfiance(m.Reseaux[i].SSID))
	}
	ecrireAuto(m)
	http.Redirect(w, r, "/wifi", http.StatusSeeOther)
}
