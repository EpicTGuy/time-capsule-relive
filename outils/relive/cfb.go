package main

// Format CFB0 d'Apple (listes de propriétés compactes d'ACP), lecture et
// écriture à l'identique : les dictionnaires gardent l'ordre de leurs clés.
// Voir outils/cfb.py pour la description du format.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

type Paire struct {
	Cle    any
	Valeur any
}

// Dict : dictionnaire ordonné (l'ordre compte pour réécrire à l'identique).
type Dict []Paire

func (d Dict) Get(cle string) any {
	for _, p := range d {
		if p.Cle == cle {
			return p.Valeur
		}
	}
	return nil
}

func (d Dict) Set(cle string, v any) Dict {
	for i, p := range d {
		if p.Cle == cle {
			d[i].Valeur = v
			return d
		}
	}
	return append(d, Paire{cle, v})
}

var epoque2001 = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

type lecteurCFB struct {
	d []byte
	i int
}

var errCFB = errors.New("CFB0 invalide")

func (l *lecteurCFB) octets(n int) ([]byte, error) {
	if l.i+n > len(l.d) {
		return nil, errCFB
	}
	b := l.d[l.i : l.i+n]
	l.i += n
	return b, nil
}

func (l *lecteurCFB) entier(exp byte) (uint64, error) {
	b, err := l.octets(1 << exp)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// fin : marqueur 0x00 (fin de tableau ou de dictionnaire).
type fin struct{}

func (l *lecteurCFB) objet() (any, error) {
	b, err := l.octets(1)
	if err != nil {
		return nil, err
	}
	m := b[0]
	t, info := m&0xF0, m&0x0F
	switch t {
	case 0x00:
		switch info {
		case 0:
			return fin{}, nil
		case 8:
			return false, nil
		case 9:
			return true, nil
		}
	case 0x10:
		v, err := l.entier(info)
		return int64(v), err
	case 0x20:
		v, err := l.entier(info)
		if info == 2 {
			return float64(math.Float32frombits(uint32(v))), err
		}
		return math.Float64frombits(v), err
	case 0x30:
		v, err := l.entier(3)
		return epoque2001.Add(time.Duration(math.Float64frombits(v) * float64(time.Second))), err
	case 0x40:
		n := int(info)
		if info == 0xF {
			x, err := l.objet()
			if err != nil {
				return nil, err
			}
			n = int(x.(int64))
		}
		b, err := l.octets(n)
		return append([]byte(nil), b...), err
	case 0x70:
		j := bytes.IndexByte(l.d[l.i:], 0)
		if j < 0 {
			return nil, errCFB
		}
		s := string(l.d[l.i : l.i+j])
		l.i += j + 1
		return s, nil
	case 0xA0:
		var liste []any
		for {
			o, err := l.objet()
			if err != nil {
				return nil, err
			}
			if _, ok := o.(fin); ok {
				return liste, nil
			}
			liste = append(liste, o)
		}
	case 0xD0:
		var d Dict
		for {
			k, err := l.objet()
			if err != nil {
				return nil, err
			}
			if _, ok := k.(fin); ok {
				return d, nil
			}
			v, err := l.objet()
			if err != nil {
				return nil, err
			}
			d = append(d, Paire{k, v})
		}
	}
	return nil, errCFB
}

func LireCFB(data []byte) (any, error) {
	if len(data) < 8 || string(data[:4]) != "CFB0" || string(data[len(data)-4:]) != "END!" {
		return nil, errCFB
	}
	l := &lecteurCFB{d: data[4 : len(data)-4]}
	o, err := l.objet()
	if err == nil && l.i != len(l.d) {
		err = errCFB
	}
	return o, err
}

func ecrireObjet(b *bytes.Buffer, o any) {
	switch v := o.(type) {
	case nil:
		b.WriteByte(0)
	case bool:
		if v {
			b.WriteByte(9)
		} else {
			b.WriteByte(8)
		}
	case int:
		ecrireObjet(b, int64(v))
	case int64:
		u := uint64(v)
		switch {
		case u < 1<<8:
			b.Write([]byte{0x10, byte(u)})
		case u < 1<<16:
			b.WriteByte(0x11)
			binary.Write(b, binary.BigEndian, uint16(u))
		case u < 1<<32:
			b.WriteByte(0x12)
			binary.Write(b, binary.BigEndian, uint32(u))
		default:
			b.WriteByte(0x13)
			binary.Write(b, binary.BigEndian, u)
		}
	case float64:
		b.WriteByte(0x23)
		binary.Write(b, binary.BigEndian, math.Float64bits(v))
	case time.Time:
		b.WriteByte(0x33)
		binary.Write(b, binary.BigEndian, math.Float64bits(v.Sub(epoque2001).Seconds()))
	case []byte:
		if len(v) < 0xF {
			b.WriteByte(0x40 | byte(len(v)))
		} else {
			b.WriteByte(0x4F)
			ecrireObjet(b, int64(len(v)))
		}
		b.Write(v)
	case string:
		b.WriteByte(0x70)
		b.WriteString(v)
		b.WriteByte(0)
	case []any:
		b.WriteByte(0xA0)
		for _, e := range v {
			ecrireObjet(b, e)
		}
		b.WriteByte(0)
	case Dict:
		b.WriteByte(0xD0)
		for _, p := range v {
			ecrireObjet(b, p.Cle)
			ecrireObjet(b, p.Valeur)
		}
		b.WriteByte(0)
	}
}

func EcrireCFB(o any) []byte {
	var b bytes.Buffer
	b.WriteString("CFB0")
	ecrireObjet(&b, o)
	b.WriteString("END!")
	return b.Bytes()
}
