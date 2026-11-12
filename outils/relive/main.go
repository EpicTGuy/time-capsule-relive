// ReLive : interface web d'administration de l'AirPort Time Capsule.
// « When Apple leaves, Time Capsule relives. »
//
//	relive -ecoute :8080 -dossier /Volumes/dk2/.seconde-vie
//
// Tourne sur la Time Capsule (Go corrigé pour NetBSD 6) et parle à ACPd en
// local. Connexion avec le mot de passe de la Time Capsule. Toute écriture de
// réglage Wi-Fi est précédée d'une sauvegarde exacte, restaurable en un clic.
package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

var (
	acp      ACP
	dossier  string
	sessions = struct {
		sync.Mutex
		m map[string]*session
	}{m: map[string]*session{}}
)

type session struct {
	mdp    string // nécessaire pour parler à ACPd ; ne quitte jamais la mémoire
	csrf   string
	expire time.Time
}

func jeton() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sessionDe(r *http.Request) *session {
	c, err := r.Cookie("relive")
	if err != nil {
		return nil
	}
	sessions.Lock()
	defer sessions.Unlock()
	s := sessions.m[c.Value]
	if s == nil || time.Now().After(s.expire) {
		delete(sessions.m, c.Value)
		return nil
	}
	s.expire = time.Now().Add(8 * time.Hour)
	return s
}

// protege : page réservée aux sessions ouvertes ; POST exige le jeton CSRF.
func protege(h func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := sessionDe(r)
		if s == nil {
			http.Redirect(w, r, "/connexion", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost &&
			subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
			http.Error(w, "jeton de sécurité invalide, rechargez la page", http.StatusForbidden)
			return
		}
		h(w, r, s)
	}
}

func base(s *session, page string) map[string]any {
	d := map[string]any{"Page": page}
	if s != nil {
		d["CSRF"] = s.csrf
	}
	return d
}

// --- Connexion ---

func connexion(w http.ResponseWriter, r *http.Request) {
	d := base(nil, "connexion")
	if r.Method == http.MethodPost {
		mdp := r.FormValue("motdepasse")
		if _, err := acp.Lire(mdp, "syNm"); err != nil {
			time.Sleep(time.Second) // freine les essais en série
			if errors.Is(err, ErrMotDePasse) {
				d["Erreur"] = "Mot de passe incorrect."
			} else {
				d["Erreur"] = "La Time Capsule ne répond pas : " + err.Error()
			}
		} else {
			id := jeton()
			sessions.Lock()
			sessions.m[id] = &session{mdp: mdp, csrf: jeton(), expire: time.Now().Add(8 * time.Hour)}
			sessions.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "relive", Value: id, Path: "/", HttpOnly: true,
				Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	afficher(w, "connexion.html", d)
}

func deconnexion(w http.ResponseWriter, r *http.Request, s *session) {
	if c, err := r.Cookie("relive"); err == nil {
		sessions.Lock()
		delete(sessions.m, c.Value)
		sessions.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "relive", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/connexion", http.StatusSeeOther)
}

// --- Tableau de bord ---

func tableau(w http.ResponseWriter, r *http.Request, s *session) {
	d := base(s, "tableau")
	p, err := acp.Lire(s.mdp, "syNm", "syAM", "syVs", "syUT", "sySI", "sySt", "laIP")
	if err != nil {
		d["Erreur"] = err.Error()
	}
	d["Nom"] = strings.TrimRight(string(p["syNm"]), "\x00")
	d["Modele"] = strings.TrimRight(string(p["syAM"]), "\x00")
	d["Version"] = strings.TrimRight(string(p["syVs"]), "\x00")
	d["Allumee"] = dureeLisible(uint32de(p["syUT"]))
	if ip := p["laIP"]; len(ip) == 4 {
		d["IP"] = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
	var capteurs []map[string]any
	if o, err := LireCFB(p["sySI"]); err == nil {
		for _, c := range o.([]any) {
			cd := c.(Dict)
			nom, _ := cd.Get("name").(string)
			val, _ := cd.Get("value").(int64)
			if strings.HasPrefix(nom, "T_") && val > 0 {
				capteurs = append(capteurs, map[string]any{"Nom": strings.TrimPrefix(nom, "T_"), "Valeur": val, "Chaud": val > 65})
			}
			if nom == "Fan_rpm" {
				d["Ventilateur"] = val
			}
		}
	}
	d["Capteurs"] = capteurs
	var problemes []string
	if o, err := LireCFB(p["sySt"]); err == nil {
		if lst, ok := o.(Dict).Get("problems").([]any); ok {
			for _, x := range lst {
				if code, ok := x.(Dict).Get("code").(string); ok {
					problemes = append(problemes, code)
				}
			}
		}
	}
	d["Problemes"] = problemes
	d["Memoire"] = lireMemoire()
	d["Disque"] = lireDisque("/Volumes/dk2")
	d["SMART"] = lireSMART("/Volumes/dk2/ShareRoot/.seconde-vie/smart.txt")
	d["Processus"] = lireProcessus()
	if fi, err := os.Stat("/Volumes/dk2/ShareRoot/immich-restic/snapshots"); err == nil {
		d["DerniereSauvegarde"] = fi.ModTime().Format("02/01/2006 15:04")
	}
	afficher(w, "tableau.html", d)
}

// --- Wi-Fi ---

type Radio struct {
	Index     int
	Bande     string
	Role      string
	SSID      string
	Canal     int64
	CanalAuto bool
	Securite  string
	Masque    bool
	Invite    bool
	MAC       string
}

var securites = map[int64]string{0: "Aucune (ouvert)", 5: "WPA2 Personnel"}

func lireWiFi(mdp string) ([]byte, Dict, error) {
	p, err := acp.Lire(mdp, "WiFi")
	if err != nil {
		return nil, nil, err
	}
	brut := p["WiFi"]
	o, err := LireCFB(brut)
	if err != nil {
		return nil, nil, err
	}
	d, ok := o.(Dict)
	if !ok {
		return nil, nil, errors.New("configuration Wi-Fi inattendue")
	}
	return brut, d, nil
}

func radios(conf Dict) []Radio {
	var res []Radio
	lst, _ := conf.Get("radios").([]any)
	for i, x := range lst {
		r := x.(Dict)
		canal, _ := r.Get("raCh").(int64)
		wm, _ := r.Get("raWM").(int64)
		st, _ := r.Get("raSt").(int64)
		rad := Radio{Index: i, Canal: canal}
		rad.SSID, _ = r.Get("raNm").(string)
		rad.CanalAuto, _ = r.Get("raCA").(bool)
		rad.Masque, _ = r.Get("raCl").(bool)
		rad.Bande = "2,4 GHz"
		if canal > 14 {
			rad.Bande = "5 GHz"
		}
		rad.Role = "Point d'accès"
		if st == 1 {
			rad.Role = "Client Wi-Fi (répéteur)"
		}
		rad.Securite = securites[wm]
		if rad.Securite == "" {
			rad.Securite = "Mode " + strconv.FormatInt(wm, 10)
		}
		if vaps, ok := r.Get("vaps").([]any); ok && len(vaps) > 0 {
			rad.Invite, _ = vaps[0].(Dict).Get("Enabled").(bool)
		}
		if mac, ok := r.Get("raMA").([]byte); ok && len(mac) == 6 {
			rad.MAC = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		}
		res = append(res, rad)
	}
	return res
}

// Reseau : un réseau vu par le dernier scan (propriété raSR), avec la radio qui l'a vu.
type Reseau struct {
	Radio    int // 0 = 5 GHz (wlan0), 1 = 2,4 GHz (wlan1)
	SSID     string
	Canal    int64
	Signal   int64 // dBm
	Securite string
	Possible bool // WPA2 personnel ou ouvert ; WPA3 seul et WPA entreprise : non pris en charge
}

// reseauxVus : résultats du dernier scan, du plus fort au plus faible, un par nom et par bande.
func reseauxVus(mdp string) ([]Reseau, error) {
	p, err := acp.Lire(mdp, "raSR")
	if err != nil {
		return nil, err
	}
	o, err := LireCFB(p["raSR"])
	if err != nil {
		return nil, err
	}
	d, _ := o.(Dict)
	meilleurs := map[string]Reseau{}
	scans, _ := d.Get("scan_results").([]any)
	for _, x := range scans {
		pi, _ := x.(Dict)
		for radio, nomIf := range []string{"wlan0", "wlan1"} {
			lst, _ := pi.Get(nomIf).([]any)
			for _, y := range lst {
				r, _ := y.(Dict)
				nom, _ := r.Get("SSID_STR").(string)
				if nom == "" {
					continue
				}
				res := Reseau{Radio: radio, SSID: nom}
				res.Canal, _ = r.Get("CHANNEL").(int64)
				res.Signal, _ = r.Get("RSSI").(int64) // entier signé stocké sur 64 bits
				res.Securite, res.Possible = "Ouvert", true
				if rsn, ok := r.Get("RSN_IE").(Dict); ok {
					res.Securite, res.Possible = "WPA3 seul (non pris en charge)", false
					auths, _ := rsn.Get("IE_KEY_RSN_AUTHSELS").([]any)
					for _, a := range auths {
						switch a {
						case int64(2):
							res.Securite, res.Possible = "WPA2", true
						case int64(1):
							if !res.Possible {
								res.Securite = "WPA entreprise (non pris en charge)"
							}
						}
					}
				}
				cle := nomIf + "|" + nom
				if m, ok := meilleurs[cle]; !ok || res.Signal > m.Signal {
					meilleurs[cle] = res
				}
			}
		}
	}
	var tous []Reseau
	for _, r := range meilleurs {
		tous = append(tous, r)
	}
	sort.Slice(tous, func(i, j int) bool { return tous[i].Signal > tous[j].Signal })
	return tous, nil
}

func dossierWiFi() string { return filepath.Join(dossier, "sauvegardes-wifi") }

func sauvegarderWiFi(brut []byte) (string, error) {
	if err := os.MkdirAll(dossierWiFi(), 0o700); err != nil {
		return "", err
	}
	nom := "wifi-" + time.Now().Format("20060102-150405") + ".cfb"
	return nom, os.WriteFile(filepath.Join(dossierWiFi(), nom), brut, 0o600)
}

func wifi(w http.ResponseWriter, r *http.Request, s *session) {
	d := base(s, "wifi")
	_, conf, err := lireWiFi(s.mdp)
	if err != nil {
		d["Erreur"] = err.Error()
	} else {
		d["Radios"] = radios(conf)
	}
	entrees, _ := os.ReadDir(dossierWiFi())
	var copies []string
	for _, e := range entrees {
		if strings.HasSuffix(e.Name(), ".cfb") {
			copies = append(copies, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(copies)))
	d["Copies"] = copies
	if res, err := reseauxVus(s.mdp); err == nil {
		d["Reseaux"] = res
	}
	m := lireAuto()
	m.Mdp, m.Base = "", nil // rien de secret vers la page
	for i := range m.Reseaux {
		m.Reseaux[i].Cle = ""
	}
	d["Auto"] = m
	d["Cable"] = map[string]string{"0": "débranché", "1": "branché, vers un réseau",
		"2": "branché, vers un appareil qui attend Internet (routeur en WAN)"}[codeCable()]
	d["Message"] = r.URL.Query().Get("ok")
	afficher(w, "wifi.html", d)
}

func wifiModifier(w http.ResponseWriter, r *http.Request, s *session) {
	brut, conf, err := lireWiFi(s.mdp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	i, _ := strconv.Atoi(r.FormValue("radio"))
	lst, _ := conf.Get("radios").([]any)
	if i < 0 || i >= len(lst) {
		http.Error(w, "radio inconnue", http.StatusBadRequest)
		return
	}
	rad := lst[i].(Dict)
	if ssid := strings.TrimSpace(r.FormValue("ssid")); ssid != "" {
		if len(ssid) > 32 {
			http.Error(w, "nom de réseau trop long (32 octets au plus)", http.StatusBadRequest)
			return
		}
		rad = rad.Set("raNm", ssid)
	}
	if mdp := r.FormValue("cle"); mdp != "" {
		if len(mdp) < 8 || len(mdp) > 63 {
			http.Error(w, "mot de passe Wi-Fi : 8 à 63 caractères", http.StatusBadRequest)
			return
		}
		rad = rad.Set("raCr", mdp)
	}
	// raWE = PSK WPA dérivée du mot de passe et du SSID, calculée par l'outil de
	// réglage et utilisée telle quelle par hostapd/wpa_supplicant : la refaire à
	// chaque changement de nom ou de mot de passe, sinon plus personne ne se connecte.
	if nom, _ := rad.Get("raNm").(string); nom != "" {
		var cle string
		switch v := rad.Get("raCr").(type) {
		case string:
			cle = v
		case []byte: // relu de l'appareil, raCr est parfois une donnée brute
			cle = string(v)
		}
		if cle != "" {
			psk, err := pbkdf2.Key(sha1.New, cle, []byte(nom), 4096, 32)
			if err != nil {
				http.Error(w, "clé WPA : "+err.Error(), http.StatusInternalServerError)
				return
			}
			rad = rad.Set("raWE", psk)
		}
	}
	if c := r.FormValue("canal"); c == "auto" {
		rad = rad.Set("raCA", true)
	} else if n, err := strconv.ParseInt(c, 10, 64); err == nil && n > 0 {
		rad = rad.Set("raCA", false).Set("raCh", n)
	}
	rad = rad.Set("raCl", r.FormValue("masque") == "on")
	lst[i] = rad
	conf = conf.Set("radios", lst)

	nom, err := sauvegarderWiFi(brut)
	if err != nil {
		http.Error(w, "sauvegarde impossible, rien n'a été modifié : "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := acp.Ecrire(s.mdp, "WiFi", EcrireCFB(conf)); err != nil {
		http.Error(w, "écriture refusée (rien n'a changé) : "+err.Error(), http.StatusBadGateway)
		return
	}
	acp.Redemarrer(s.mdp)
	afficher(w, "redemarrage.html", map[string]any{"Raison": "Réglages Wi-Fi appliqués. Copie de l'ancienne configuration : " + nom})
}

// configClient : la radio `radio` devient cliente de `ssid` (client simple, pas le DWDS d'Apple que seuls les
// routeurs Apple acceptent) ; l'autre reste ou redevient le Wi-Fi de la Time Capsule, avec le nom et le mot de
// passe de celui-ci. canal 0 = celui que choisira la radio ; cle vide = réseau ouvert.
func configClient(conf Dict, radio int, ssid, cle string, canal int64) (Dict, error) {
	if ssid == "" || len(ssid) > 32 || (radio != 0 && radio != 1) {
		return nil, errors.New("nom de réseau (32 octets au plus) ou bande invalide")
	}
	if cle != "" && (len(cle) < 8 || len(cle) > 63) {
		return nil, errors.New("mot de passe Wi-Fi : 8 à 63 caractères (vide pour un réseau ouvert)")
	}
	lst, _ := conf.Get("radios").([]any)
	if len(lst) != 2 {
		return nil, errors.New("configuration Wi-Fi inattendue (2 radios attendues)")
	}
	// copies : Dict.Set modifie sur place, la configuration reçue ne doit pas changer
	lst = append([]any(nil), lst...)
	cible, autre := append(Dict(nil), lst[radio].(Dict)...), append(Dict(nil), lst[1-radio].(Dict)...)
	// Réglages du Wi-Fi de la Time Capsule : ceux de la radio point d'accès actuelle (la cible si les deux le sont).
	modele := cible
	if st, _ := cible.Get("raSt").(int64); st == 1 {
		modele = autre
	}
	if st, _ := autre.Get("raSt").(int64); st == 1 { // l'autre était cliente : elle redevient point d'accès
		if st2, _ := modele.Get("raSt").(int64); st2 == 1 {
			return nil, errors.New("aucune radio en point d'accès : restaurez d'abord une configuration sauvegardée")
		}
		for _, k := range []string{"raNm", "raCr", "raWE", "raWM", "raCl"} {
			autre = autre.Set(k, modele.Get(k))
		}
		autre = autre.Set("raSt", int64(0)).Set("raCA", true)
	}
	cible = cible.Set("raSt", int64(1)).Set("dWDS", false).Set("raNm", ssid)
	if canal > 0 {
		cible = cible.Set("raCA", false).Set("raCh", canal)
	}
	if cle == "" {
		cible = cible.Set("raWM", int64(0))
	} else {
		psk, err := pbkdf2.Key(sha1.New, cle, []byte(ssid), 4096, 32) // raWE : voir wifiModifier
		if err != nil {
			return nil, err
		}
		cible = cible.Set("raWM", int64(5)).Set("raCr", cle).Set("raWE", psk)
	}
	lst[radio], lst[1-radio] = cible, autre
	return append(Dict(nil), conf...).Set("radios", lst), nil
}

// wifiRejoindre : formulaire « Rejoindre un réseau Wi-Fi ». Au redémarrage, demarrage.sh lance tc-pont : Time
// Capsule joignable par ce Wi-Fi et, sans câble, partage de la connexion.
func wifiRejoindre(w http.ResponseWriter, r *http.Request, s *session) {
	radio, _ := strconv.Atoi(r.FormValue("radio"))
	ssid := strings.TrimSpace(r.FormValue("autre"))
	canal := int64(0)
	if ssid == "" { // « radio|canal|nom »
		if parts := strings.SplitN(r.FormValue("reseau"), "|", 3); len(parts) == 3 {
			radio, _ = strconv.Atoi(parts[0])
			canal, _ = strconv.ParseInt(parts[1], 10, 64)
			ssid = parts[2]
		}
	}
	brut, conf, err := lireWiFi(s.mdp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	nouvelle, err := configClient(conf, radio, ssid, r.FormValue("cle"), canal)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	nom, err := sauvegarderWiFi(brut)
	if err != nil {
		http.Error(w, "sauvegarde impossible, rien n'a été modifié : "+err.Error(), http.StatusInternalServerError)
		return
	}
	m := lireAuto()
	m.definirConfiance(ssid, r.FormValue("confiance") == "1")
	if err := ecrireAuto(m); err != nil {
		http.Error(w, "liste des réseaux de confiance non enregistrée, rien n'a changé : "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	if err := acp.Ecrire(s.mdp, "WiFi", EcrireCFB(nouvelle)); err != nil {
		http.Error(w, "écriture refusée (rien n'a changé) : "+err.Error(), http.StatusBadGateway)
		return
	}
	acp.Redemarrer(s.mdp)
	afficher(w, "redemarrage.html", map[string]any{"Raison": "La Time Capsule rejoint « " + ssid + " ». Elle aura " +
		"une nouvelle adresse sur ce réseau (voir le routeur, ou airport-time-capsule-wi-fi.local). " +
		"Pour revenir en arrière : Wi-Fi → Configurations sauvegardées → " + nom})
}

func wifiRestaurer(w http.ResponseWriter, r *http.Request, s *session) {
	nom := filepath.Base(r.FormValue("copie"))
	data, err := os.ReadFile(filepath.Join(dossierWiFi(), nom))
	if err != nil || !strings.HasSuffix(nom, ".cfb") {
		http.Error(w, "copie introuvable", http.StatusNotFound)
		return
	}
	if _, err := LireCFB(data); err != nil {
		http.Error(w, "copie illisible", http.StatusBadRequest)
		return
	}
	if brut, _, err := lireWiFi(s.mdp); err == nil {
		sauvegarderWiFi(brut)
	}
	if err := acp.Ecrire(s.mdp, "WiFi", data); err != nil {
		http.Error(w, "écriture refusée : "+err.Error(), http.StatusBadGateway)
		return
	}
	acp.Redemarrer(s.mdp)
	afficher(w, "redemarrage.html", map[string]any{"Raison": "Configuration Wi-Fi « " + nom + " » restaurée."})
}

// --- Journaux et système ---

func journaux(w http.ResponseWriter, r *http.Request, s *session) {
	d := base(s, "journaux")
	p, err := acp.Lire(s.mdp, "logm")
	if err != nil {
		d["Erreur"] = err.Error()
	}
	var lignes []string
	for _, l := range strings.Split(string(p["logm"]), "\x00") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if i := strings.Index(l, ">"); strings.HasPrefix(l, "<") && i > 0 {
			l = l[i+1:]
		}
		lignes = append(lignes, l)
	}
	for i, j := 0, len(lignes)-1; i < j; i, j = i+1, j-1 {
		lignes[i], lignes[j] = lignes[j], lignes[i]
	}
	d["Lignes"] = lignes
	if b, err := os.ReadFile("/mnt/Memory/seconde-vie.log"); err == nil {
		d["SecondeVie"] = string(b)
	}
	afficher(w, "journaux.html", d)
}

func systeme(w http.ResponseWriter, r *http.Request, s *session) {
	d := base(s, "systeme")
	d["Memoire"] = lireMemoire()
	d["Processus"] = lireProcessus()
	d["Noyau"] = strings.TrimSpace(commande("uname", "-sr"))
	afficher(w, "systeme.html", d)
}

func redemarrer(w http.ResponseWriter, r *http.Request, s *session) {
	if err := acp.Redemarrer(s.mdp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	afficher(w, "redemarrage.html", map[string]any{"Raison": "Redémarrage demandé."})
}

func main() {
	ecoute := flag.String("ecoute", ":80", "adresse d'écoute HTTP (redirige vers HTTPS si -https est actif)")
	ecouteTLS := flag.String("https", ":443", "adresse d'écoute HTTPS (vide = HTTP seul)")
	flag.StringVar(&acp.Adresse, "acp", "127.0.0.1:5009", "adresse d'ACPd")
	flag.StringVar(&dossier, "dossier", "/Volumes/dk2/.seconde-vie", "dossier de travail (copies de réglages)")
	flag.Parse()
	debug.SetMemoryLimit(12 << 20)

	sous, _ := fs.Sub(webFS, "web")

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sous)))
	mux.HandleFunc("/connexion", connexion)
	mux.HandleFunc("POST /deconnexion", protege(deconnexion))
	mux.HandleFunc("GET /{$}", protege(tableau))
	mux.HandleFunc("GET /wifi", protege(wifi))
	mux.HandleFunc("POST /wifi/modifier", protege(wifiModifier))
	mux.HandleFunc("POST /wifi/restaurer", protege(wifiRestaurer))
	mux.HandleFunc("POST /wifi/rejoindre", protege(wifiRejoindre))
	mux.HandleFunc("POST /auto/activer", protege(autoActiver))
	mux.HandleFunc("POST /auto/desactiver", protege(autoDesactiver))
	mux.HandleFunc("POST /auto/ajouter", protege(autoAjouter))
	mux.HandleFunc("POST /auto/liste", protege(autoListe))
	go automate()
	mux.HandleFunc("GET /journaux", protege(journaux))
	mux.HandleFunc("GET /systeme", protege(systeme))
	mux.HandleFunc("POST /systeme/redemarrer", protege(redemarrer))

	if *ecouteTLS == "" {
		log.Printf("ReLive à l'écoute sur %s (HTTP)", *ecoute)
		srv := &http.Server{Addr: *ecoute, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(srv.ListenAndServe())
	}
	cert, err := certificat(dossier)
	if err != nil {
		log.Fatalf("certificat HTTPS : %v", err)
	}
	// HTTP : redirection vers HTTPS (les navigateurs tapent souvent l'adresse sans « https:// »)
	go func() {
		redir := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hote := r.Host
			if h, _, err := net.SplitHostPort(hote); err == nil {
				hote = h
			}
			if _, port, _ := net.SplitHostPort(*ecouteTLS); port != "" && port != "443" {
				hote = net.JoinHostPort(hote, port)
			}
			http.Redirect(w, r, "https://"+hote+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		srv := &http.Server{Addr: *ecoute, Handler: redir, ReadHeaderTimeout: 10 * time.Second}
		log.Printf("redirection HTTP %s -> HTTPS", *ecoute)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("HTTP : %v", err)
		}
	}()
	log.Printf("ReLive à l'écoute sur %s (HTTPS)", *ecouteTLS)
	srv := &http.Server{Addr: *ecouteTLS, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
