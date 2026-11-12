package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Aller-retour à l'octet près sur un relevé réel (sauvegardes/, hors dépôt).
func TestCFBAllerRetour(t *testing.T) {
	brut, err := os.ReadFile("../../sauvegardes/acp-20261028-2132.json")
	if err != nil {
		t.Skip("relevé absent :", err)
	}
	var doc struct {
		Proprietes map[string]struct {
			Type int    `json:"type"`
			Hex  string `json:"hex"`
		} `json:"proprietes"`
	}
	if err := json.Unmarshal(brut, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for nom, p := range doc.Proprietes {
		if p.Type != 13 || p.Hex == "" {
			continue
		}
		b, _ := hex.DecodeString(p.Hex)
		o, err := LireCFB(b)
		if err != nil {
			t.Fatalf("%s : %v", nom, err)
		}
		if !bytes.Equal(EcrireCFB(o), b) {
			t.Fatalf("%s : réécriture différente", nom)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("seulement %d propriétés CFB0", n)
	}
	t.Logf("%d propriétés CFB0 relues et réécrites à l'identique", n)
}
