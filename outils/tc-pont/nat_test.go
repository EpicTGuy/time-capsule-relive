package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

var (
	macApp     = []byte{0x02, 0, 0, 0, 0, 0xaa}
	macLAN     = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	macWifi    = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	macRouteur = [6]byte{0x02, 0, 0, 0, 0, 0x03}
	ipApp      = [4]byte{10, 42, 42, 100}
	ipNous     = [4]byte{192, 168, 1, 23}
	ipLoin     = [4]byte{93, 184, 216, 34}
)

type envoi struct {
	fd int
	t  []byte
}

func natEssai() (*nat, *[]envoi) {
	var envois []envoi
	n := nouveauNAT(ipNous, netip.MustParsePrefix("10.42.42.0/24"), macWifi, macLAN, 7)
	n.envoyer = func(fd int, t []byte) { envois = append(envois, envoi{fd, append([]byte(nil), t...)}) }
	n.routeur, n.connu = macRouteur, true
	return n, &envois
}

// trame : Ethernet + IPv4 + charge (en-tête L4 compris), sommes de contrôle justes.
func trame(dstMAC, srcMAC []byte, src, dst [4]byte, proto byte, l4 []byte) []byte {
	t := make([]byte, 14+20+len(l4))
	copy(t[0:6], dstMAC)
	copy(t[6:12], srcMAC)
	t[12], t[13] = 0x08, 0x00
	ip := t[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(ip[6:], 0x4000) // DF
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:], somme(ip))
	copy(t[34:], l4)
	poserSommeL4(t)
	return t
}

func pseudo(t []byte) []byte {
	l4 := t[34:]
	p := make([]byte, 12+len(l4))
	copy(p[0:8], t[26:34])
	p[9] = t[23]
	binary.BigEndian.PutUint16(p[10:], uint16(len(l4)))
	copy(p[12:], l4)
	return p
}

func poserSommeL4(t []byte) {
	l4 := t[34:]
	switch t[23] {
	case 6:
		l4[16], l4[17] = 0, 0
		binary.BigEndian.PutUint16(l4[16:], somme(pseudo(t)))
	case 17:
		l4[6], l4[7] = 0, 0
		binary.BigEndian.PutUint16(l4[6:], somme(pseudo(t)))
	case 1:
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[2:], somme(l4))
	}
}

// sommesJustes : une somme de contrôle juste fait que le total, somme comprise, vaut 0 (après complément).
func sommesJustes(t *testing.T, tr []byte) {
	t.Helper()
	if somme(tr[14:34]) != 0 {
		t.Errorf("somme IP fausse")
	}
	switch tr[23] {
	case 6, 17:
		if tr[23] == 17 && tr[40] == 0 && tr[41] == 0 {
			return
		}
		if somme(pseudo(tr)) != 0 {
			t.Errorf("somme TCP/UDP fausse")
		}
	case 1:
		if somme(tr[34:]) != 0 {
			t.Errorf("somme ICMP fausse")
		}
	}
}

func segment(src, dst uint16, drapeaux byte, donnees string) []byte {
	l4 := make([]byte, 20+len(donnees))
	binary.BigEndian.PutUint16(l4[0:], src)
	binary.BigEndian.PutUint16(l4[2:], dst)
	binary.BigEndian.PutUint32(l4[4:], 0x01020304)
	l4[12], l4[13] = 5<<4, drapeaux
	binary.BigEndian.PutUint16(l4[14:], 65535)
	copy(l4[20:], donnees)
	return l4
}

func TestNATAllerRetourTCP(t *testing.T) {
	n, envois := natEssai()
	syn := trame(macLAN, macApp, ipApp, ipLoin, 6, segment(51000, 443, 0x02, "bonjour"))
	if !n.sortant(syn, 3) {
		t.Fatal("SYN non traduit")
	}
	s := (*envois)[0]
	if s.fd != 7 || [6]byte(s.t[0:6]) != macRouteur || [6]byte(s.t[6:12]) != [6]byte(macWifi) {
		t.Fatalf("mauvaise sortie : fd %d, MAC %x → %x", s.fd, s.t[6:12], s.t[0:6])
	}
	if [4]byte(s.t[26:30]) != ipNous || s.t[22] != 63 {
		t.Fatalf("source %v, TTL %d", s.t[26:30], s.t[22])
	}
	port := binary.BigEndian.Uint16(s.t[34:])
	if port < natPremier {
		t.Fatalf("port %d hors de la plage de traduction", port)
	}
	sommesJustes(t, s.t)

	rep := trame(macWifi, macRouteur[:], ipLoin, ipNous, 6, segment(443, port, 0x12, "salut"))
	if !n.entrant(rep) {
		t.Fatal("réponse non traduite")
	}
	r := (*envois)[1]
	if r.fd != 3 || [6]byte(r.t[0:6]) != [6]byte(macApp) || [4]byte(r.t[30:34]) != ipApp ||
		binary.BigEndian.Uint16(r.t[36:]) != 51000 {
		t.Fatalf("retour faux : fd %d, %x, %v:%d", r.fd, r.t[0:6], r.t[30:34], binary.BigEndian.Uint16(r.t[36:]))
	}
	sommesJustes(t, r.t)

	// même flux : même port ; la pile gVisor garde les ports bas
	n.sortant(trame(macLAN, macApp, ipApp, ipLoin, 6, segment(51000, 443, 0x10, "")), 3)
	if binary.BigEndian.Uint16((*envois)[2].t[34:]) != port {
		t.Fatal("même flux, autre port")
	}
	if n.entrant(trame(macWifi, macRouteur[:], ipLoin, ipNous, 6, segment(443, 22, 0x02, ""))) {
		t.Fatal("port 22 (Time Capsule elle-même) pris par la traduction")
	}
}

func TestNATUDPEtPing(t *testing.T) {
	n, envois := natEssai()
	udp := make([]byte, 8+5)
	binary.BigEndian.PutUint16(udp[0:], 5353)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], 13)
	copy(udp[8:], "dns ?")
	n.sortant(trame(macLAN, macApp, ipApp, [4]byte{192, 168, 1, 1}, 17, udp), 3)
	sommesJustes(t, (*envois)[0].t)

	sans := trame(macLAN, macApp, ipApp, ipLoin, 17, udp)
	sans[40], sans[41] = 0, 0 // UDP sans somme de contrôle
	n.sortant(sans, 3)
	if o := (*envois)[1].t; o[40] != 0 || o[41] != 0 {
		t.Fatal("UDP sans somme : 0 doit rester 0")
	}

	echo := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'}
	n.sortant(trame(macLAN, macApp, ipApp, ipLoin, 1, echo), 3)
	e := (*envois)[2].t
	sommesJustes(t, e)
	id := binary.BigEndian.Uint16(e[38:])
	rep := append([]byte(nil), e[34:]...)
	rep[0] = 0
	n.entrant(trame(macWifi, macRouteur[:], ipLoin, ipNous, 1, rep))
	r := (*envois)[3].t
	if binary.BigEndian.Uint16(r[38:]) != 0x1234 || [4]byte(r[30:34]) != ipApp {
		t.Fatalf("réponse d'écho : id %x vers %v (traduit en %x)", binary.BigEndian.Uint16(r[38:]), r[30:34], id)
	}
	sommesJustes(t, r)
}

func TestNATErreurICMP(t *testing.T) {
	n, envois := natEssai()
	n.sortant(trame(macLAN, macApp, ipApp, ipLoin, 6, segment(51000, 443, 0x10, "gros paquet")), 3)
	sortie := (*envois)[0].t
	// « fragmentation nécessaire » d'un routeur au sujet de ce paquet : en-tête IP + 8 octets cités
	cite := sortie[14 : 14+28]
	icmp := append([]byte{3, 4, 0, 0, 0, 0, 0x05, 0xdc}, cite...)
	n.entrant(trame(macWifi, macRouteur[:], [4]byte{80, 10, 0, 1}, ipNous, 1, icmp))
	if len(*envois) != 2 {
		t.Fatal("erreur ICMP non relayée")
	}
	r := (*envois)[1].t
	in := r[42:]
	if [4]byte(r[30:34]) != ipApp || [4]byte(in[12:16]) != ipApp || binary.BigEndian.Uint16(in[20:]) != 51000 {
		t.Fatalf("erreur mal traduite : vers %v, cité %v:%d", r[30:34], in[12:16], binary.BigEndian.Uint16(in[20:]))
	}
	sommesJustes(t, r)
	if somme(in[:20]) != 0 {
		t.Error("somme de l'en-tête cité fausse")
	}
}

func TestNATFiltres(t *testing.T) {
	n, envois := natEssai()
	if n.sortant(trame(macLAN, macApp, ipApp, [4]byte{10, 42, 42, 1}, 6, segment(5000, 445, 0x02, "")), 3) {
		t.Error("paquet pour 10.42.42.1 (le noyau) traduit")
	}
	if n.sortant(trame([]byte{2, 9, 9, 9, 9, 9}, macApp, ipApp, ipLoin, 6, segment(5000, 443, 0x02, "")), 3) {
		t.Error("paquet pour une autre MAC traduit")
	}
	frag := trame(macLAN, macApp, ipApp, ipLoin, 17, make([]byte, 8))
	frag[20] = 0x20 // MF
	if n.sortant(frag, 3) {
		t.Error("fragment traduit")
	}
	if n.entrant(trame(macWifi, macRouteur[:], ipLoin, ipNous, 6, segment(443, 40000, 0x02, ""))) != true ||
		len(*envois) != 0 {
		t.Error("port de traduction inconnu : doit être jeté sans rien envoyer")
	}
}

func TestNATExpiration(t *testing.T) {
	n, _ := natEssai()
	now := time.Now()
	n.maintenant = func() time.Time { return now }
	n.sortant(trame(macLAN, macApp, ipApp, ipLoin, 17, make([]byte, 8)), 3)
	n.sortant(trame(macLAN, macApp, ipApp, ipLoin, 6, segment(1, 2, 0x02, "")), 3)
	now = now.Add(3 * time.Minute)
	n.nettoyer()
	if len(n.parApp) != 1 || len(n.parPort) != 1 {
		t.Fatalf("après 3 min : %d traductions (attendu : seule celle de TCP)", len(n.parApp))
	}
}
