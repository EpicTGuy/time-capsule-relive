package main

// Relevés de l'appareil : outils du système d'Apple (vmstat, df, ps), relevé
// SMART écrit par demarrage.sh, propriétés ACP.

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Memoire struct {
	TotalMo, LibreMo, SwapMo, SwapUtiliseMo int
}

type Disque struct {
	TailleGo, UtiliseGo, LibreGo float64
	Pourcent                     int
}

type AttributSMART struct {
	ID               int
	Nom              string
	Valeur, Seuil    int
	Brut             int64
	Critique, Alarme bool
}

type SMART struct {
	Present     bool
	Date        time.Time
	Temperature int64
	Heures      int64
	Sain        bool
	Attributs   []AttributSMART
}

type Processus struct {
	SambaNb, SambaMo int
	WireGuard        bool
	Tailscale        bool
	Relive           bool
}

func commande(nom string, args ...string) string {
	c := exec.Command(nom, args...)
	c.Env = append(os.Environ(), "PATH=/bin:/sbin:/usr/bin:/usr/sbin")
	out, _ := c.Output()
	return string(out)
}

func lireMemoire() Memoire {
	var m Memoire
	page := 4096
	vals := map[string]int{}
	for _, l := range strings.Split(commande("vmstat", "-s"), "\n") {
		champs := strings.Fields(l)
		if len(champs) < 2 {
			continue
		}
		n, err := strconv.Atoi(champs[0])
		if err != nil {
			continue
		}
		vals[strings.Join(champs[1:], " ")] = n
	}
	if p := vals["bytes per page"]; p > 0 {
		page = p
	}
	mo := func(pages int) int { return pages * page / (1 << 20) }
	m.TotalMo, m.LibreMo = mo(vals["pages managed"]), mo(vals["pages free"])
	m.SwapMo, m.SwapUtiliseMo = mo(vals["swap pages"]), mo(vals["swap pages in use"])
	return m
}

func lireDisque(chemin string) Disque {
	var d Disque
	lignes := strings.Split(strings.TrimSpace(commande("df", "-k", chemin)), "\n")
	if len(lignes) < 2 {
		return d
	}
	c := strings.Fields(lignes[len(lignes)-1])
	if len(c) < 5 {
		return d
	}
	ko := func(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v / 1024 / 1024 }
	d.TailleGo, d.UtiliseGo, d.LibreGo = ko(c[1]), ko(c[2]), ko(c[3])
	d.Pourcent, _ = strconv.Atoi(strings.TrimSuffix(c[4], "%"))
	return d
}

var nomsSMART = map[int]string{
	1: "Erreurs de lecture", 3: "Démarrage du moteur", 4: "Démarrages / arrêts", 5: "Secteurs réalloués",
	7: "Erreurs de positionnement", 9: "Heures de fonctionnement", 10: "Relances du moteur",
	12: "Mises sous tension", 187: "Erreurs non corrigées", 190: "Température (flux d'air)",
	194: "Température", 197: "Secteurs en attente", 198: "Secteurs illisibles", 199: "Erreurs de câble (CRC)",
}

var smartCritiques = map[int]bool{5: true, 187: true, 197: true, 198: true}

func lireSMART(chemin string) SMART {
	s := SMART{Sain: true}
	info, err := os.Stat(chemin)
	if err != nil {
		return s
	}
	data, err := os.ReadFile(chemin)
	if err != nil {
		return s
	}
	s.Present, s.Date = true, info.ModTime()
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		c := strings.Fields(sc.Text())
		if len(c) < 4 {
			continue
		}
		id, e1 := strconv.Atoi(c[0])
		val, e2 := strconv.Atoi(c[1])
		seuil, e3 := strconv.Atoi(c[2])
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		brutTxt := c[len(c)-1]
		for i, x := range c {
			if x == "Lifetime" && i > 0 {
				brutTxt = c[i-1]
			}
		}
		brut, _ := strconv.ParseInt(brutTxt, 10, 64)
		a := AttributSMART{ID: id, Nom: nomsSMART[id], Valeur: val, Seuil: seuil, Brut: brut, Critique: smartCritiques[id]}
		if a.Nom == "" {
			a.Nom = "Attribut " + c[0]
		}
		if (a.Critique && brut > 0) || (seuil > 0 && val <= seuil && id != 190) {
			a.Alarme, s.Sain = true, false
		}
		switch id {
		case 194:
			s.Temperature = brut
		case 9:
			s.Heures = brut
		}
		s.Attributs = append(s.Attributs, a)
	}
	return s
}

func lireProcessus() Processus {
	var p Processus
	for _, l := range strings.Split(commande("ps", "-axo", "rss,comm"), "\n") {
		c := strings.Fields(l)
		if len(c) < 2 {
			continue
		}
		rss, _ := strconv.Atoi(c[0])
		switch {
		case strings.HasSuffix(c[1], "smbd"):
			p.SambaNb++
			p.SambaMo += rss / 1024
		case strings.HasSuffix(c[1], "wg-tc"):
			p.WireGuard = true
		case strings.HasSuffix(c[1], "tailscaled"):
			p.Tailscale = true
		}
	}
	return p
}

func dureeLisible(s uint32) string {
	d := time.Duration(s) * time.Second
	j := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	if j > 0 {
		return strconv.Itoa(j) + " j " + strconv.Itoa(h) + " h"
	}
	return strconv.Itoa(h) + " h " + strconv.Itoa(m) + " min"
}
