// tc-dhcp : client DHCP minimal pour l'interface Wi-Fi client de la Time Capsule (mode relais).
// Le dhclient d'Apple (ISC 4, dans le crunchprog) s'arrête sans rien dire juste après PREINIT
// quand on le lance sur wlan1 ; celui-ci passe par BPF (trames Ethernet brutes), sans dépendre
// de la table de routage : l'interface n'a pas encore d'adresse et bridge0 porte la route par défaut.
//
//	tc-dhcp -i wlan1 -mac 02:00:00:… -script /tmp/relais/dhclient-script [-nom airport-time-capsule]
//	tc-dhcp -i bcmeth0 -mac d4:47:7e:… -sonde [-ignorer 10.42.42.254]
//
// -sonde : un serveur DHCP répond-il sur cette interface ? Deux DISCOVER, sans rien demander ensuite ; affiche
// le serveur et sa MAC et sort avec le code 0 s'il y a une offre (hors serveurs -ignorer), 3 sinon (autre code : erreur). Sert à savoir si le
// câble Ethernet mène à une box (réseau à rejoindre) ou à un appareil qui attend une adresse (routeur en WAN).
//
// L'adresse MAC est passée en argument : net.InterfaceByName échoue sur le NetBSD 6 d'Apple
// (« route ip+net: no such network interface »).
//
// Le script reçoit les mêmes variables que dhclient-script (reason=BOUND|RENEW|EXPIRE,
// new_ip_address, new_subnet_mask, new_routers, new_domain_name_servers, old_ip_address, interface).
// Le bail est renouvelé à mi-durée ; s'il expire, retour à la découverte.
//
// À compiler avec le Go corrigé pour NetBSD 6 (outils/construire-tc.sh).
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	discover = 1
	offer    = 2
	request  = 3
	ack      = 5
	nak      = 6
)

type bail struct {
	source              net.HardwareAddr // MAC d'où vient la réponse
	ip, masque, serveur net.IP
	routeurs, dns       []net.IP
	duree               time.Duration
}

type client struct {
	mac    net.HardwareAddr
	nom    string
	fd     int
	trames chan []byte
}

var bavard = flag.Bool("v", false, "journal détaillé (trames BPF)")

func ouvrirBPF(nom string) (int, error) {
	var fd int
	var err error
	for i := 0; i < 16; i++ {
		if fd, err = syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDWR, 0); err == nil {
			break
		}
	}
	if err != nil {
		return -1, fmt.Errorf("aucun /dev/bpf libre : %w", err)
	}
	var ifr [144]byte // struct ifreq de NetBSD 6 (16 + sockaddr_storage)
	copy(ifr[:], nom)
	un := 1
	// Filtre noyau : IPv4, UDP, non fragmenté, port destination 68. Sans lui, tout le trafic du
	// Wi-Fi remonte et les réponses DHCP se perdent derrière (tampon BPF plein).
	filtre := []syscall.BpfInsn{
		{Code: 0x28, K: 12},                   // ldh [12]
		{Code: 0x15, Jt: 0, Jf: 8, K: 0x800},  // jeq IPv4
		{Code: 0x30, K: 23},                   // ldb [23]
		{Code: 0x15, Jt: 0, Jf: 6, K: 17},     // jeq UDP
		{Code: 0x28, K: 20},                   // ldh [20]
		{Code: 0x45, Jt: 4, Jf: 0, K: 0x1fff}, // jset fragment
		{Code: 0xb1, K: 14},                   // ldxb 4*([14]&0xf)
		{Code: 0x48, K: 16},                   // ldh [x+16]
		{Code: 0x15, Jt: 0, Jf: 1, K: 68},     // jeq 68
		{Code: 0x06, K: 0xffff},               // ret tout
		{Code: 0x06, K: 0},                    // ret rien
	}
	prog := syscall.BpfProgram{Len: uint32(len(filtre)), Insns: &filtre[0]}
	for _, io := range []struct {
		req uintptr
		arg unsafe.Pointer
	}{
		{syscall.BIOCSETIF, unsafe.Pointer(&ifr[0])},
		{syscall.BIOCIMMEDIATE, unsafe.Pointer(&un)},
		{syscall.BIOCSHDRCMPLT, unsafe.Pointer(&un)},
		{syscall.BIOCSETF, unsafe.Pointer(&prog)},
	} {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), io.req, uintptr(io.arg)); e != 0 {
			syscall.Close(fd)
			return -1, fmt.Errorf("ioctl 0x%x : %w", io.req, e)
		}
	}
	return fd, nil
}

// lire découpe les tampons BPF en trames Ethernet (en-tête bpf_hdr : caplen à 8, hdrlen à 16).
func (c *client) lire() {
	var blen int32
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(c.fd), syscall.BIOCGBLEN, uintptr(unsafe.Pointer(&blen)))
	if blen <= 0 {
		blen = 4096
	}
	buf := make([]byte, blen)
	if *bavard {
		log.Printf("BPF : tampon de %d octets", blen)
	}
	for {
		n, err := syscall.Read(c.fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			log.Fatalf("lecture BPF : %v", err)
		}
		for p := 0; p+18 <= n; {
			caplen := int(binary.LittleEndian.Uint32(buf[p+8:]))
			hdrlen := int(binary.LittleEndian.Uint16(buf[p+16:]))
			if p+hdrlen+caplen > n {
				break
			}
			select { // jamais bloquant : mieux vaut perdre une vieille trame que la réponse attendue
			case c.trames <- append([]byte(nil), buf[p+hdrlen:p+hdrlen+caplen]...):
			default:
			}
			p += (hdrlen + caplen + 3) &^ 3
		}
	}
}

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

// envoyer diffuse un message DHCP (Ethernet + IPv4 0.0.0.0 → 255.255.255.255 + UDP 68 → 67).
func (c *client) envoyer(dhcp []byte) error {
	udp := make([]byte, 8+len(dhcp))
	binary.BigEndian.PutUint16(udp[0:], 68)
	binary.BigEndian.PutUint16(udp[2:], 67)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], dhcp)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	copy(ip[16:], net.IPv4bcast.To4())
	binary.BigEndian.PutUint16(ip[10:], somme(ip))
	eth := make([]byte, 14, 14+20+len(udp))
	copy(eth, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(eth[6:], c.mac)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	trame := append(append(eth, ip...), udp...)
	_, err := syscall.Write(c.fd, trame)
	return err
}

func (c *client) message(typ byte, xid uint32, ciaddr net.IP, demande, serveur net.IP) []byte {
	m := make([]byte, 240, 320)
	m[0], m[1], m[2] = 1, 1, 6
	binary.BigEndian.PutUint32(m[4:], xid)
	if ciaddr != nil {
		copy(m[12:], ciaddr.To4())
	} else {
		m[10] = 0x80 // réponse en diffusion : l'interface n'a pas encore d'adresse
	}
	copy(m[28:], c.mac)
	binary.BigEndian.PutUint32(m[236:], 0x63825363)
	opt := func(code byte, v []byte) { m = append(append(m, code, byte(len(v))), v...) }
	opt(53, []byte{typ})
	opt(61, append([]byte{1}, c.mac...))
	if c.nom != "" {
		opt(12, []byte(c.nom))
	}
	if demande != nil {
		opt(50, demande.To4())
	}
	if serveur != nil {
		opt(54, serveur.To4())
	}
	opt(55, []byte{1, 3, 6, 51})
	return append(m, 255)
}

// attendre renvoie la première réponse DHCP pour xid (type, bail) avant l'échéance.
func (c *client) attendre(xid uint32, echeance time.Time) (byte, *bail, error) {
	for {
		select {
		case t := <-c.trames:
			if len(t) < 14+20+8+240 || binary.BigEndian.Uint16(t[12:]) != 0x0800 || t[14+9] != 17 {
				continue
			}
			ihl := int(t[14]&0x0f) * 4
			u := t[14+ihl:]
			if len(u) < 8+240 || binary.BigEndian.Uint16(u[2:]) != 68 {
				continue
			}
			d := u[8:]
			if *bavard {
				log.Printf("DHCP reçu : op %d xid %08x (attendu %08x)", d[0], binary.BigEndian.Uint32(d[4:]), xid)
			}
			if d[0] != 2 || binary.BigEndian.Uint32(d[4:]) != xid || binary.BigEndian.Uint32(d[236:]) != 0x63825363 {
				continue
			}
			b := &bail{ip: net.IP(append([]byte(nil), d[16:20]...)), source: net.HardwareAddr(append([]byte(nil), t[6:12]...))}
			var typ byte
			for o := d[240:]; len(o) >= 2 && o[0] != 255; {
				if o[0] == 0 {
					o = o[1:]
					continue
				}
				l := int(o[1])
				if len(o) < 2+l {
					break
				}
				v := o[2 : 2+l]
				switch o[0] {
				case 53:
					typ = v[0]
				case 1:
					b.masque = net.IP(append([]byte(nil), v...))
				case 3:
					b.routeurs = ips(v)
				case 6:
					b.dns = ips(v)
				case 51:
					b.duree = time.Duration(binary.BigEndian.Uint32(v)) * time.Second
				case 54:
					b.serveur = net.IP(append([]byte(nil), v...))
				}
				o = o[2+l:]
			}
			return typ, b, nil
		case <-time.After(time.Until(echeance)):
			return 0, nil, errors.New("pas de réponse")
		}
	}
}

func ips(v []byte) []net.IP {
	var r []net.IP
	for i := 0; i+4 <= len(v); i += 4 {
		r = append(r, net.IP(append([]byte(nil), v[i:i+4]...)))
	}
	return r
}

func nouveauXid() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// obtenir : DISCOVER → OFFER → REQUEST → ACK, nouvelles tentatives espacées (4 s, 8 s… 64 s).
func (c *client) obtenir() *bail {
	pause := 4 * time.Second
	for {
		xid := nouveauXid()
		if *bavard {
			log.Printf("DISCOVER xid %08x", xid)
		}
		if err := c.envoyer(c.message(discover, xid, nil, nil, nil)); err != nil {
			log.Printf("envoi : %v", err)
		} else if typ, o, err := c.attendre(xid, time.Now().Add(pause)); err == nil && typ == offer {
			if b := c.demander(xid, nil, o.ip, o.serveur); b != nil {
				return b
			}
		}
		time.Sleep(time.Second)
		if pause < 64*time.Second {
			pause *= 2
		}
	}
}

func (c *client) demander(xid uint32, ciaddr, ip, serveur net.IP) *bail {
	for essai := 0; essai < 3; essai++ {
		var m []byte
		if ciaddr != nil {
			m = c.message(request, xid, ciaddr, nil, nil) // renouvellement : ciaddr seul
		} else {
			m = c.message(request, xid, nil, ip, serveur)
		}
		if err := c.envoyer(m); err != nil {
			log.Printf("envoi : %v", err)
			return nil
		}
		// Le pilote Broadcom remet chaque diffusion reçue plusieurs fois sur wlan1 (jusqu'à 8 copies
		// vues par tcpdump) : on ignore les OFFER en double et on attend l'ACK jusqu'à l'échéance.
		echeance := time.Now().Add(4 * time.Second)
		for {
			typ, b, err := c.attendre(xid, echeance)
			if err != nil {
				break
			}
			if typ == ack {
				if b.duree == 0 {
					b.duree = time.Hour
				}
				return b
			}
			if typ == nak {
				return nil
			}
		}
	}
	return nil
}

// sonder : 0 si un serveur DHCP (hors ignorés) fait une offre, 3 sinon, 1 si l'envoi échoue.
func sonder(c *client, ignores []string) int {
	for essai := 0; essai < 2; essai++ {
		xid := nouveauXid()
		if err := c.envoyer(c.message(discover, xid, nil, nil, nil)); err != nil {
			log.Printf("envoi : %v", err)
			return 1
		}
		echeance := time.Now().Add(3 * time.Second)
		for {
			typ, o, err := c.attendre(xid, echeance)
			if err != nil {
				break
			}
			if typ != offer || o.serveur == nil {
				continue
			}
			ignore := false
			for _, i := range ignores {
				ignore = ignore || i == o.serveur.String()
			}
			if !ignore {
				fmt.Println(o.serveur, o.source)
				return 0
			}
		}
	}
	return 3
}

func joindre(l []net.IP) string {
	s := make([]string, len(l))
	for i, ip := range l {
		s[i] = ip.String()
	}
	return strings.Join(s, " ")
}

func lancer(script, raison, iface string, b, ancien *bail) {
	log.Printf("%s %v", raison, func() any {
		if b != nil {
			return b.ip
		}
		return "-"
	}())
	if script == "" {
		return
	}
	cmd := exec.Command(script)
	cmd.Env = append(os.Environ(), "reason="+raison, "interface="+iface)
	if ancien != nil {
		cmd.Env = append(cmd.Env, "old_ip_address="+ancien.ip.String())
	}
	if b != nil {
		masque := b.masque
		if masque == nil {
			masque = net.IP(net.CIDRMask(24, 32))
		}
		cmd.Env = append(cmd.Env, "new_ip_address="+b.ip.String(), "new_subnet_mask="+masque.String(),
			"new_routers="+joindre(b.routeurs), "new_domain_name_servers="+joindre(b.dns),
			fmt.Sprintf("new_dhcp_lease_time=%d", int(b.duree.Seconds())))
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("script : %v", err)
	}
}

func main() {
	nomIf := flag.String("i", "wlan1", "interface")
	script := flag.String("script", "", "script appelé à chaque changement de bail")
	nom := flag.String("nom", "", "nom d'hôte annoncé (option 12)")
	adresse := flag.String("mac", "", "adresse MAC de l'interface (ifconfig … ether)")
	sonde := flag.Bool("sonde", false, "seulement chercher un serveur DHCP (code de sortie 0 s'il répond)")
	ignorer := flag.String("ignorer", "", "sonde : serveurs à ne pas compter, séparés par des virgules")
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime)

	mac, err := net.ParseMAC(*adresse)
	if err != nil || len(mac) != 6 {
		log.Fatalf("-mac invalide : %q", *adresse)
	}
	fd, err := ouvrirBPF(*nomIf)
	if err != nil {
		log.Fatal(err)
	}
	c := &client{mac: mac, nom: *nom, fd: fd, trames: make(chan []byte, 64)}
	go c.lire()
	if *sonde {
		os.Exit(sonder(c, strings.Split(*ignorer, ",")))
	}

	var b *bail
	for {
		if b == nil {
			b = c.obtenir()
			lancer(*script, "BOUND", *nomIf, b, nil)
		}
		expire := time.Now().Add(b.duree)
		time.Sleep(b.duree / 2)
		var nouveau *bail
		for nouveau == nil && time.Now().Before(expire) {
			nouveau = c.demander(nouveauXid(), b.ip, nil, nil)
			if nouveau == nil {
				time.Sleep(min(time.Until(expire)/2+time.Second, 5*time.Minute))
			}
		}
		if nouveau == nil {
			lancer(*script, "EXPIRE", *nomIf, nil, b)
			b = nil
			continue
		}
		raison := "RENEW"
		if !nouveau.ip.Equal(b.ip) {
			raison = "BOUND"
		}
		lancer(*script, raison, *nomIf, nouveau, b)
		b = nouveau
	}
}
