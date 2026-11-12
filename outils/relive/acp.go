package main

// Client ACP minimal (protocole d'administration AirPort), d'après le client
// Python de TimeCapsuleSMB (GPL-3.0) et nos relevés : lecture (0x14) et
// écriture (0x15) de propriétés. Sur la Time Capsule, ACPd écoute en local
// (127.0.0.1:5009) : le mot de passe ne quitte pas l'appareil.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"net"
	"time"
)

var cleStatique = [16]byte{0x5b, 0x6f, 0xaf, 0x5d, 0x9d, 0x5b, 0x0e, 0x13, 0x51, 0xf2, 0xda, 0x1d, 0xe7, 0xe8, 0xd6, 0x73}

const (
	acpLire    = 0x14
	acpEcrire  = 0x15
	tailleTete = 128
)

// ErrMotDePasse : ACPd a refusé la commande (mot de passe faux).
var ErrMotDePasse = errors.New("mot de passe refusé par la Time Capsule")

type ACP struct {
	Adresse string // ex. 127.0.0.1:5009
}

func adler(b []byte) uint32 { return adler32.Checksum(b) }

func entete(commande uint32, mdp string, corps []byte, drapeaux uint32) []byte {
	h := make([]byte, tailleTete)
	copy(h[0:4], "acpp")
	binary.BigEndian.PutUint32(h[4:], 0x00030001)
	binary.BigEndian.PutUint32(h[12:], adler(corps))
	binary.BigEndian.PutUint32(h[16:], uint32(len(corps)))
	binary.BigEndian.PutUint32(h[20:], drapeaux)
	binary.BigEndian.PutUint32(h[28:], commande)
	pw := make([]byte, 32)
	copy(pw, mdp)
	for i := 0; i < 32; i++ {
		h[48+i] = byte(i+0x55) ^ cleStatique[i%16] ^ pw[i]
	}
	binary.BigEndian.PutUint32(h[8:], adler(h))
	return h
}

func element(nom string, valeur []byte) []byte {
	e := make([]byte, 12, 12+len(valeur))
	copy(e[0:4], nom)
	binary.BigEndian.PutUint32(e[8:], uint32(len(valeur)))
	return append(e, valeur...)
}

func (a ACP) echange(commande uint32, mdp string, corps []byte, drapeaux uint32) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", a.Adresse, 10*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write(append(entete(commande, mdp, corps, drapeaux), corps...)); err != nil {
		c.Close()
		return nil, err
	}
	rep := make([]byte, tailleTete)
	if _, err := io.ReadFull(c, rep); err != nil {
		c.Close()
		return nil, err
	}
	if string(rep[0:4]) != "acpp" {
		c.Close()
		return nil, errors.New("réponse ACP invalide")
	}
	if code := int32(binary.BigEndian.Uint32(rep[32:])); code != 0 {
		c.Close()
		return nil, ErrMotDePasse
	}
	return c, nil
}

// Lire renvoie les valeurs brutes des propriétés demandées (absentes si refusées).
func (a ACP) Lire(mdp string, noms ...string) (map[string][]byte, error) {
	var corps []byte
	for _, n := range noms {
		corps = append(corps, element(n, []byte{0, 0, 0, 0})...)
	}
	c, err := a.echange(acpLire, mdp, corps, 4)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	res := map[string][]byte{}
	for vus := 0; vus < len(noms); vus++ {
		t := make([]byte, 12)
		if _, err := io.ReadFull(c, t); err != nil {
			return res, err
		}
		nom, drapeaux, n := string(t[0:4]), binary.BigEndian.Uint32(t[4:]), binary.BigEndian.Uint32(t[8:])
		if nom == "\x00\x00\x00\x00" {
			break
		}
		v := make([]byte, n)
		if _, err := io.ReadFull(c, v); err != nil {
			return res, err
		}
		if drapeaux&1 == 0 {
			res[nom] = v
		}
	}
	return res, nil
}

// Ecrire écrit une propriété (entier 32 bits ou octets).
func (a ACP) Ecrire(mdp, nom string, valeur []byte) error {
	c, err := a.echange(acpEcrire, mdp, element(nom, valeur), 0)
	if err != nil {
		return err
	}
	defer c.Close()
	t := make([]byte, 12)
	if _, err := io.ReadFull(c, t); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(t[4:])&1 != 0 {
		return fmt.Errorf("écriture de %s refusée", nom)
	}
	return nil
}

func (a ACP) Redemarrer(mdp string) error { return a.Ecrire(mdp, "acRB", []byte{0, 0, 0, 0}) }

func uint32de(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
