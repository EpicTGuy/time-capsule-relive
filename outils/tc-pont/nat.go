package main

// Partage de connexion du mode relais : traduction d'adresses (NAT), comme une box. Le noyau tient 10.42.42.1 sur
// bridge0 (DHCP, ARP, ping, services de la Time Capsule) et son routage est coupé : il ignore les paquets des
// appareils vers l'extérieur. tc-pont les lit par BPF (Wi-Fi de la Time Capsule, câble), leur donne son adresse
// et un de ses ports (32768–65535) et les écrit sur le Wi-Fi client vers la MAC du routeur ; les réponses font le
// chemin inverse. Seuls les en-têtes changent : sommes de contrôle ajustées par différence (RFC 1624).
//
// Remplace un routeur virtuel gVisor qui terminait chaque connexion dans une seconde pile TCP : 21 Mbit/s,
// processeur saturé (11/11/2026). Spec : docs/spec-nat.md.

import (
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	natPremier = 32768 // la pile gVisor garde 16000–32767 pour la Time Capsule elle-même
	natDernier = 65535
)

// cleNAT : un flux vu d'un côté (protocole, adresse, port ; identifiant pour le ping).
type cleNAT struct {
	proto byte
	ip    [4]byte
	port  uint16
}

type traduction struct {
	app  cleNAT  // l'appareil
	mac  [6]byte // sa MAC
	fd   int     // l'interface où il a été vu (y écrire passe de toute façon par le pont du noyau)
	port uint16  // notre port côté Wi-Fi
	vu   time.Time
	fin  bool // TCP : FIN ou RST vu, la traduction expire vite
}

type nat struct {
	mu         sync.Mutex
	parApp     map[cleNAT]*traduction
	parPort    map[cleNAT]*traduction // proto + notre port
	prochain   uint16
	ip         [4]byte // notre adresse Wi-Fi
	reseau     netip.Prefix
	macWifi    [6]byte
	macLAN     [6]byte
	routeur    [6]byte // MAC de la passerelle Wi-Fi (résolue par la pile gVisor)
	connu      bool
	fdWifi     int
	envoyer    func(fd int, t []byte) // syscall.Write, remplacé dans les tests
	maintenant func() time.Time
}

func nouveauNAT(ip [4]byte, reseau netip.Prefix, macWifi, macLAN net.HardwareAddr, fdWifi int) *nat {
	n := &nat{parApp: map[cleNAT]*traduction{}, parPort: map[cleNAT]*traduction{}, prochain: natPremier,
		ip: ip, reseau: reseau, fdWifi: fdWifi, maintenant: time.Now,
		envoyer: func(fd int, t []byte) { syscall.Write(fd, t) }}
	copy(n.macWifi[:], macWifi)
	copy(n.macLAN[:], macLAN)
	return n
}

// suivreRouteur : MAC de la passerelle, redemandée chaque minute à la pile gVisor (ARP).
func (n *nat) suivreRouteur(s *stack.Stack, passerelle, local tcpip.Address) {
	for ; ; time.Sleep(time.Minute) {
		s.GetLinkAddress(1, passerelle, local, ipv4.ProtocolNumber, func(r stack.LinkResolutionResult) {
			if r.Err == nil && len(r.LinkAddress) == 6 {
				n.mu.Lock()
				copy(n.routeur[:], r.LinkAddress)
				n.connu = true
				n.mu.Unlock()
			}
		})
	}
}

// expirer : UDP 2 min (DNS 20 s), ping 30 s, TCP 2 h sans trafic ou 1 min après FIN/RST.
func (n *nat) expirer() {
	for ; ; time.Sleep(30 * time.Second) {
		n.nettoyer()
	}
}

func (n *nat) nettoyer() {
	now := n.maintenant()
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, t := range n.parApp {
		duree := 2 * time.Minute
		switch {
		case t.app.proto == 6 && t.fin:
			duree = time.Minute
		case t.app.proto == 6:
			duree = 2 * time.Hour
		case t.app.proto == 1:
			duree = 30 * time.Second
		}
		if now.Sub(t.vu) > duree {
			delete(n.parApp, k)
			delete(n.parPort, cleNAT{t.app.proto, n.ip, t.port})
		}
	}
}

// traduire : traduction de l'appareil (créée au besoin), nil si plus aucun port libre.
func (n *nat) traduire(app cleNAT, mac []byte, fd int) *traduction {
	if t := n.parApp[app]; t != nil {
		t.mac, t.fd = [6]byte(mac), fd
		return t
	}
	for essai := 0; essai <= natDernier-natPremier; essai++ {
		p := n.prochain
		if n.prochain++; n.prochain == 0 {
			n.prochain = natPremier
		}
		if _, pris := n.parPort[cleNAT{app.proto, n.ip, p}]; !pris {
			t := &traduction{app: app, mac: [6]byte(mac), fd: fd, port: p}
			n.parApp[app], n.parPort[cleNAT{app.proto, n.ip, p}] = t, t
			return t
		}
	}
	return nil
}

// ipv4Simple : en-tête IPv4 et sa longueur, ou 0 si la trame n'est pas un IPv4 non fragmenté utilisable.
func ipv4Simple(t []byte) int {
	if len(t) < 14+20 || t[12] != 0x08 || t[13] != 0x00 || t[14]>>4 != 4 {
		return 0
	}
	ihl := int(t[14]&0x0f) * 4
	if ihl < 20 || len(t) < 14+ihl+8 || binary.BigEndian.Uint16(t[20:22])&0x3fff != 0 { // MF ou décalage
		return 0
	}
	return ihl
}

// champs : position (dans la trame) du port à traduire, source ou destination, et de la somme de contrôle.
// Ping : l'identifiant tient lieu de port.
func champs(t []byte, ihl int, source bool) (port, somme int, ok bool) {
	l4 := 14 + ihl
	switch t[23] {
	case 6:
		if len(t) < l4+20 {
			return 0, 0, false
		}
		port, somme = l4+2, l4+16
		if source {
			port = l4
		}
	case 17:
		port, somme = l4+2, l4+6
		if source {
			port = l4
		}
	case 1:
		port, somme = l4+4, l4+2
	default:
		return 0, 0, false
	}
	return port, somme, true
}

// sortant : trame d'un appareil (Wi-Fi de la Time Capsule ou câble) ; vrai si traduite et envoyée.
func (n *nat) sortant(t []byte, fd int) bool {
	ihl := ipv4Simple(t)
	if ihl == 0 || [6]byte(t[0:6]) != n.macLAN {
		return false
	}
	dst := [4]byte(t[30:34])
	if n.reseau.Contains(netip.AddrFrom4(dst)) || dst == n.ip || t[22] <= 1 {
		return false // pour le noyau (10.42.42.x), pour nous, ou TTL épuisé
	}
	if t[23] == 1 && t[14+ihl] != 8 {
		return false // ICMP : seules les demandes d'écho sortent
	}
	port, cs, ok := champs(t, ihl, true)
	if !ok {
		return false
	}
	n.mu.Lock()
	tr := n.traduire(cleNAT{t[23], [4]byte(t[26:30]), binary.BigEndian.Uint16(t[port:])}, t[6:12], fd)
	if tr == nil || !n.connu { // plus de port libre, ou MAC du routeur pas encore résolue : paquet perdu
		n.mu.Unlock()
		return true
	}
	tr.vu = n.maintenant()
	if t[23] == 6 && t[14+ihl+13]&0x05 != 0 { // FIN ou RST
		tr.fin = true
	}
	routeur, nport := n.routeur, tr.port
	n.mu.Unlock()

	changer(t, ihl, 26, port, cs, n.ip, nport)
	copy(t[0:6], routeur[:])
	copy(t[6:12], n.macWifi[:])
	n.envoyer(n.fdWifi, t)
	return true
}

// entrant : trame reçue sur le Wi-Fi client ; vrai si elle était pour un appareil (traduite et envoyée).
func (n *nat) entrant(t []byte) bool {
	ihl := ipv4Simple(t)
	if ihl == 0 || [4]byte(t[30:34]) != n.ip || t[22] <= 1 {
		return false
	}
	if t[23] == 1 {
		switch t[14+ihl] {
		case 0: // réponse d'écho
		case 3, 11, 12: // erreur au sujet d'un de nos flux (« fragmentation nécessaire »…)
			return n.erreurICMP(t, ihl)
		default:
			return false
		}
	}
	port, cs, ok := champs(t, ihl, false)
	if !ok {
		return false
	}
	p := binary.BigEndian.Uint16(t[port:])
	if p < natPremier {
		return false // pour la pile gVisor (la Time Capsule elle-même)
	}
	n.mu.Lock()
	tr := n.parPort[cleNAT{t[23], n.ip, p}]
	if tr == nil {
		n.mu.Unlock()
		return true // port de traduction inconnu : rien pour la pile non plus
	}
	tr.vu = n.maintenant()
	if t[23] == 6 && t[14+ihl+13]&0x05 != 0 {
		tr.fin = true
	}
	app, mac, fd := tr.app, tr.mac, tr.fd
	n.mu.Unlock()

	changer(t, ihl, 30, port, cs, app.ip, app.port)
	copy(t[0:6], mac[:])
	copy(t[6:12], n.macLAN[:])
	n.envoyer(fd, t)
	return true
}

// erreurICMP : l'en-tête cité (notre paquet sortant) est remis à l'adresse et au port de l'appareil ; sommes
// recalculées en entier (message court).
func (n *nat) erreurICMP(t []byte, ihl int) bool {
	ic := 14 + ihl
	in := ic + 8
	if len(t) < in+20 || t[in]>>4 != 4 {
		return false
	}
	ihl2 := int(t[in]&0x0f) * 4
	if len(t) < in+ihl2+8 || [4]byte(t[in+12:in+16]) != n.ip {
		return false
	}
	proto := t[in+9]
	pos := in + ihl2 // port source cité (TCP, UDP) ; identifiant pour un écho cité
	if proto == 1 {
		pos += 4
	} else if proto != 6 && proto != 17 {
		return false
	}
	n.mu.Lock()
	tr := n.parPort[cleNAT{proto, n.ip, binary.BigEndian.Uint16(t[pos:])}]
	if tr == nil {
		n.mu.Unlock()
		return false
	}
	app, mac, fd := tr.app, tr.mac, tr.fd
	n.mu.Unlock()

	copy(t[in+12:in+16], app.ip[:])
	binary.BigEndian.PutUint16(t[pos:], app.port)
	t[in+10], t[in+11] = 0, 0
	binary.BigEndian.PutUint16(t[in+10:], somme(t[in:in+ihl2]))
	total := int(binary.BigEndian.Uint16(t[16:18]))
	if 14+total > len(t) || total < ihl+8 {
		return false
	}
	t[ic+2], t[ic+3] = 0, 0
	binary.BigEndian.PutUint16(t[ic+2:], somme(t[ic:14+total]))
	// en-tête extérieur : destination = l'appareil
	ancien := [4]byte(t[30:34])
	copy(t[30:34], app.ip[:])
	t[22]--
	ajuster(t[24:26], ancien[:], app.ip[:])
	ajuster(t[24:26], []byte{t[22] + 1, 0}, []byte{t[22], 0})
	copy(t[0:6], mac[:])
	copy(t[6:12], n.macLAN[:])
	n.envoyer(fd, t)
	return true
}

// changer : adresse (source à 26 ou destination à 30) et port changés, TTL diminué, sommes ajustées.
// La somme TCP/UDP couvre le pseudo-en-tête (donc l'adresse) ; celle de l'ICMP, non. UDP sans somme : 0 reste 0.
func changer(t []byte, ihl, adresse, port, cs int, ip [4]byte, p uint16) {
	ancienIP := [4]byte(t[adresse : adresse+4])
	var ancienPort [2]byte
	copy(ancienPort[:], t[port:port+2])
	var nouveauPort [2]byte
	binary.BigEndian.PutUint16(nouveauPort[:], p)

	copy(t[adresse:adresse+4], ip[:])
	copy(t[port:port+2], nouveauPort[:])
	ajuster(t[24:26], ancienIP[:], ip[:])
	ajuster(t[24:26], []byte{t[22], t[23]}, []byte{t[22] - 1, t[23]})
	t[22]--

	sommeL4 := t[cs : cs+2]
	if t[23] == 17 && sommeL4[0] == 0 && sommeL4[1] == 0 {
		return
	}
	if t[23] != 1 {
		ajuster(sommeL4, ancienIP[:], ip[:])
	}
	ajuster(sommeL4, ancienPort[:], nouveauPort[:])
	if t[23] == 17 && sommeL4[0] == 0 && sommeL4[1] == 0 {
		sommeL4[0], sommeL4[1] = 0xff, 0xff // 0 voudrait dire « pas de somme » en UDP
	}
}

// ajuster : somme de contrôle Internet mise à jour quand ancien devient nouveau (RFC 1624 : HC' = ~(~HC + ~m + m')).
// ancien et nouveau ont la même longueur paire.
func ajuster(sc []byte, ancien, nouveau []byte) {
	s := uint32(^binary.BigEndian.Uint16(sc))
	for i := 0; i+1 < len(ancien); i += 2 {
		s += uint32(^binary.BigEndian.Uint16(ancien[i:])) + uint32(binary.BigEndian.Uint16(nouveau[i:]))
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	binary.BigEndian.PutUint16(sc, ^uint16(s))
}

// somme : somme de contrôle Internet (RFC 1071).
func somme(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

// partager : lit les trames des appareils sur le Wi-Fi de la Time Capsule (et le câble) et les traduit. Répond aussi
// aux ARP pour toute adresse hors du réseau partagé : un appareil qui garde, après une coupure, l'adresse et le
// routeur du réseau précédent (192.168.1.1…) nous envoie alors ses paquets, traduits comme les autres. Pas aux
// sondes (source 0.0.0.0 : un iPhone refuserait chaque bail) ni aux annonces (source = cible).
func partager(n *nat, interfaces []string) {
	for _, nom := range interfaces {
		fd, err := ouvrirBPF(nom, filtreCable(n.macLAN[:]))
		if err != nil {
			log.Printf("partage : %s : %v", nom, err)
			continue
		}
		go lireLAN(n, fd)
	}
	go n.expirer()
	log.Printf("partage par traduction d'adresses sur %v (réseau %v)", interfaces, n.reseau)
}

func lireLAN(n *nat, fd int) {
	var blen int32
	ioctl(fd, syscall.BIOCGBLEN, unsafe.Pointer(&blen))
	if blen <= 0 {
		blen = 4096
	}
	buf := make([]byte, blen)
	for {
		nb, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			log.Fatalf("lecture BPF : %v", err)
		}
		for p := 0; p+18 <= nb; {
			caplen := int(binary.LittleEndian.Uint32(buf[p+8:]))
			hdrlen := int(binary.LittleEndian.Uint16(buf[p+16:]))
			if p+hdrlen+caplen > nb {
				break
			}
			t := buf[p+hdrlen : p+hdrlen+caplen]
			p += (hdrlen + caplen + 3) &^ 3
			if !n.sortant(t, fd) {
				n.arp(t, fd)
			}
		}
	}
}

func (n *nat) arp(t []byte, fd int) {
	if len(t) < 42 || t[12] != 0x08 || t[13] != 0x06 || t[20] != 0 || t[21] != 1 {
		return
	}
	src, cible := [4]byte(t[28:32]), [4]byte(t[38:42])
	if src == [4]byte{} || src == cible || n.reseau.Contains(netip.AddrFrom4(cible)) {
		return // le noyau répond pour 10.42.42.x
	}
	rep := make([]byte, 42)
	copy(rep[0:6], t[22:28])
	copy(rep[6:12], n.macLAN[:])
	copy(rep[12:22], t[12:22])
	rep[21] = 2
	copy(rep[22:28], n.macLAN[:])
	copy(rep[28:32], cible[:])
	copy(rep[32:38], t[22:28])
	copy(rep[38:42], src[:])
	n.envoyer(fd, rep)
}

// relaisDNS : le noyau ne sert pas de DNS ; les appareils interrogent 10.42.42.1:53 (annoncé par dhcpd), tc-pont
// répond par un socket du noyau et transmet par la pile du Wi-Fi client au serveur de la box. Les appareils gardent
// ainsi le même serveur quel que soit le réseau rejoint. UDP seulement.
func relaisDNS(s *stack.Stack, ici, amont netip.Addr) {
	var c *net.UDPConn
	for {
		var err error
		if c, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ici, 53))); err == nil {
			break
		}
		log.Printf("relais DNS : %v (nouvel essai dans 15 s)", err) // l'adresse arrive avec relais.sh
		time.Sleep(15 * time.Second)
	}
	vers := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(amont.As4()), Port: 53}
	buf := make([]byte, 1500)
	for {
		nb, app, err := c.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		q := append([]byte(nil), buf[:nb]...)
		go func() {
			d, err := gonet.DialUDP(s, nil, &vers, ipv4.ProtocolNumber)
			if err != nil {
				return
			}
			defer d.Close()
			d.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := d.Write(q); err != nil {
				return
			}
			r := make([]byte, 4096)
			if n, err := d.Read(r); err == nil {
				c.WriteToUDP(r[:n], app)
			}
		}()
	}
}
