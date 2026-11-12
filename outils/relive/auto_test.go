package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func radioAP(nom string) Dict {
	return Dict{{"raSt", int64(0)}, {"raNm", nom}, {"raCr", "motdepasse-tc"}, {"raWM", int64(5)}, {"raWE", []byte("x")},
		{"raCl", false}, {"raCh", int64(36)}, {"raCA", true}, {"dWDS", true}}
}

func etat(c Dict, i int) (int64, string) {
	r := c.Get("radios").([]any)[i].(Dict)
	st, _ := r.Get("raSt").(int64)
	nom, _ := r.Get("raNm").(string)
	return st, nom
}

func TestConfigClient(t *testing.T) {
	base := Dict{{"radios", []any{radioAP("TC"), radioAP("TC")}}}
	c, err := configClient(base, 0, "Box5", "cle-de-la-box", 44)
	if err != nil {
		t.Fatal(err)
	}
	if st, nom := etat(c, 0); st != 1 || nom != "Box5" {
		t.Fatalf("radio 0 : %d %q", st, nom)
	}
	if st, nom := etat(c, 1); st != 0 || nom != "TC" {
		t.Fatalf("radio 1 doit rester le Wi-Fi de la Time Capsule : %d %q", st, nom)
	}
	// passer la cliente sur l'autre bande : la radio 0 redevient le Wi-Fi « TC »
	c2, err := configClient(c, 1, "Box", "cle-de-la-box", 6)
	if err != nil {
		t.Fatal(err)
	}
	if st, nom := etat(c2, 0); st != 0 || nom != "TC" {
		t.Fatalf("radio 0 doit redevenir « TC » : %d %q", st, nom)
	}
	if st, nom := etat(c2, 1); st != 1 || nom != "Box" {
		t.Fatalf("radio 1 : %d %q", st, nom)
	}
	if _, err := configClient(base, 0, "Box", "court", 0); err == nil {
		t.Fatal("mot de passe trop court accepté")
	}
	if radioCliente(base) != -1 || radioCliente(c2) != 1 {
		t.Fatal("radioCliente")
	}
}

func TestMeilleurReseau(t *testing.T) {
	connus := []ReseauConnu{{SSID: "box", Radio: 1}, {SSID: "box", Radio: 0}, {SSID: "voisin", Radio: 1}}
	vus := []Reseau{
		{SSID: "box", Radio: 1, Signal: -50, Possible: true},
		{SSID: "box", Radio: 0, Signal: -58, Possible: true},
		{SSID: "inconnu", Radio: 1, Signal: -30, Possible: true},
		{SSID: "voisin", Radio: 1, Signal: -40, Possible: false},
	}
	if c, _, ok := meilleurReseau(connus, vus); !ok || c.Radio != 0 {
		t.Fatalf("5 GHz à -58 contre 2,4 GHz à -50 : attendu 5 GHz, eu %+v", c)
	}
	vus[1].Signal = -65
	if c, _, _ := meilleurReseau(connus, vus); c.Radio != 1 {
		t.Fatalf("5 GHz à -65 contre 2,4 GHz à -50 : attendu 2,4 GHz, eu %+v", c)
	}
	if _, _, ok := meilleurReseau(connus[2:], vus); ok {
		t.Fatal("réseau impossible (WPA3 seul…) choisi")
	}
}

func TestConfiance(t *testing.T) {
	ancien := dossier
	dossier = t.TempDir()
	defer func() { dossier = ancien }()
	m := ModeAuto{Mdp: "mot-de-passe-piege", Reseaux: []ReseauConnu{{SSID: "maison", Cle: "cle-piege-1234"}}}
	m.definirConfiance("maison", true)
	m.definirConfiance("hotel", true)
	m.definirConfiance("hotel", false)
	m.definirConfiance("maison", true) // pas de doublon
	if err := ecrireAuto(m); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dossier, "reseaux-confiance.txt"))
	if err != nil || string(b) != "maison\n" {
		t.Fatalf("liste de confiance : %q, %v", b, err)
	}
	if strings.Contains(string(b), "piege") {
		t.Fatal("un secret est passé dans la liste de confiance")
	}
	if !lireAuto().deConfiance("maison") || lireAuto().deConfiance("hotel") {
		t.Fatal("confiance mal relue")
	}
}
