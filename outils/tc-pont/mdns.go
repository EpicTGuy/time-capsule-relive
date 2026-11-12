package main

// Relais Bonjour (mDNS) : le mDNSResponder d'Apple n'annonce les services (SMB, Time Machine…) que sur
// bridge0, et la pile de tc-pont est invisible pour lui. Un socket du noyau (port 5353 partagé, groupe
// 224.0.0.251) lui repose chaque question reçue par le Wi-Fi — il ignore l'unicast venu de sa propre adresse
// mais répond à une question multicast posée depuis le port 5353 local — et entend ses réponses et annonces,
// rediffusées sur le Wi-Fi avec l'adresse Wi-Fi à la place des siennes.
//
// Câble branché, le relais se tait : nos rediffusions reviendraient à mDNSResponder par le câble, il y
// verrait un conflit sur son nom d'hôte (même nom, autre adresse) et se renommerait ; le Mac la voit alors
// directement de toute façon.

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var groupeMDNS = tcpip.AddrFrom4([4]byte{224, 0, 0, 251})

// sauterNom avance après un nom DNS (étiquettes ou pointeur de compression).
func sauterNom(m []byte, p int) int {
	for p < len(m) {
		l := int(m[p])
		switch {
		case l == 0:
			return p + 1
		case l&0xc0 == 0xc0:
			return p + 2
		default:
			p += 1 + l
		}
	}
	return -1
}

// reecrire remplace dans les enregistrements A les adresses de la Time Capsule (locales) par celle du Wi-Fi.
// Le message est modifié sur place : même longueur, aucune recompression. Renvoie faux si illisible.
func reecrire(m []byte, locales map[[4]byte]bool, wifi [4]byte) bool {
	if len(m) < 12 {
		return false
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	rr := int(binary.BigEndian.Uint16(m[6:])) + int(binary.BigEndian.Uint16(m[8:])) + int(binary.BigEndian.Uint16(m[10:]))
	p := 12
	for i := 0; i < qd; i++ {
		if p = sauterNom(m, p); p < 0 || p+4 > len(m) {
			return false
		}
		p += 4
	}
	for i := 0; i < rr; i++ {
		if p = sauterNom(m, p); p < 0 || p+10 > len(m) {
			return false
		}
		typ := binary.BigEndian.Uint16(m[p:])
		l := int(binary.BigEndian.Uint16(m[p+8:]))
		p += 10
		if p+l > len(m) {
			return false
		}
		if typ == 1 && l == 4 {
			var a [4]byte
			copy(a[:], m[p:p+4])
			if locales[a] {
				copy(m[p:p+4], wifi[:])
			}
		}
		p += l
	}
	return true
}

// adressesLocales : adresses IPv4 du noyau (bridge0 : DHCP du câble, 169.254…), par SIOCGIFCONF —
// net.Interfaces échoue sur ce NetBSD 6.
func adressesLocales() map[[4]byte]bool {
	r := map[[4]byte]bool{}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return r
	}
	defer syscall.Close(fd)
	buf := make([]byte, 8192)
	ifc := struct {
		Len int32
		Buf uintptr
	}{int32(len(buf)), uintptr(unsafe.Pointer(&buf[0]))}
	if err := ioctl(fd, syscall.SIOCGIFCONF, unsafe.Pointer(&ifc)); err != nil {
		return r
	}
	// struct ifreq : nom[16] + sockaddr (sa_len variable, au moins la taille de l'union : 128 sur NetBSD 6)
	for p := 0; p+16+2 <= int(ifc.Len); {
		sa := buf[p+16:]
		l := int(sa[0])
		if sa[1] == syscall.AF_INET && l >= 8 {
			var a [4]byte
			copy(a[:], sa[4:8])
			if a[0] != 127 && a[0] != 0 { // ni boucle locale, ni 0.0.0.0 (dhclient d'ACPd sans bail)
				r[a] = true
			}
		}
		p += 16 + max(l, 128)
	}
	return r
}

// noyau5353 : socket du noyau sur le port mDNS (partagé avec mDNSResponder), abonné au groupe.
func noyau5353() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 5353}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	// Abonnement sur une adresse précise de bridge0 : « interface quelconque » échoue (« can't assign requested
	// address ») tant qu'aucune route par défaut n'existe, au démarrage sans câble. Sortie multicast forcée
	// sur la même adresse : sans câble, la route par défaut (le routeur, injoignable) passe en « reject ».
	var e syscall.Errno = syscall.EADDRNOTAVAIL
	for a := range adressesLocales() {
		mreq := [8]byte{224, 0, 0, 251, a[0], a[1], a[2], a[3]} // struct ip_mreq : groupe, interface
		if _, _, e = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP,
			uintptr(unsafe.Pointer(&mreq[0])), 8, 0); e == 0 {
			syscall.SetsockoptInet4Addr(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, a)
			return fd, nil
		}
	}
	syscall.Close(fd)
	return -1, e
}

// questionApple : envoyée depuis une adresse précise de bridge0, port 5353. Sans câble ni route par défaut,
// un socket non attaché émet avec la source 0.0.0.0, que mDNSResponder ignore.
func questionApple(m []byte, groupe *syscall.SockaddrInet4) error {
	var src [4]byte
	for a := range adressesLocales() {
		if src[0] == 0 || a[0] != 169 { // l'adresse DHCP (câble) ou celle du relais plutôt que 169.254
			src = a
		}
	}
	if src[0] == 0 {
		return syscall.EADDRNOTAVAIL
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 5353, Addr: src}); err != nil {
		return err
	}
	syscall.SetsockoptInet4Addr(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, src)
	return syscall.Sendto(fd, m, 0, groupe)
}

// cableBranche : vrai si le câble mène à un réseau (état « 1 » noté par relais.sh, fonction cable, appelée
// toutes les 5 à 30 s par la garde et la surveillance de demarrage.sh, dans /tmp/relais/cable ; « 2 » = câble
// vers un routeur en WAN, « 0 » = rien). Faute d'information récente, on le suppose : relais en pause, ce qui
// est sans risque. (Lancer brconfig d'ici reste bloqué sur ce NetBSD 6.)
func cableBranche() bool {
	fi, err := os.Stat("/tmp/relais/cable")
	if err != nil || time.Since(fi.ModTime()) > 2*time.Minute {
		return true
	}
	b, err := os.ReadFile("/tmp/relais/cable")
	return err != nil || strings.TrimSpace(string(b)) == "1"
}

func relaisMDNS(s *stack.Stack, wifi [4]byte) {
	var wq waiter.Queue
	ep, terr := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		log.Printf("mDNS : %v", terr)
		return
	}
	ep.SocketOptions().SetReuseAddress(true)
	ep.SetSockOpt(&tcpip.MulticastInterfaceOption{NIC: 1})
	if terr := ep.Bind(tcpip.FullAddress{Port: 5353}); terr != nil {
		log.Printf("mDNS : Bind : %v", terr)
		return
	}
	// l'abonnement de la NIC ne suffit pas : gVisor ne remet le multicast qu'aux sockets abonnés
	if terr := ep.SetSockOpt(&tcpip.AddMembershipOption{NIC: 1, MulticastAddr: groupeMDNS}); terr != nil {
		log.Printf("mDNS : abonnement au groupe : %v", terr)
		return
	}
	cote := gonet.NewUDPConn(&wq, ep)
	fd, err := noyau5353()
	for err != nil { // au démarrage, bridge0 n'a pas encore d'adresse
		log.Printf("mDNS : socket du noyau : %v (nouvel essai dans 15 s)", err)
		time.Sleep(15 * time.Second)
		fd, err = noyau5353()
	}
	var actif atomic.Bool
	go func() {
		for {
			c := cableBranche()
			if actif.Load() == c {
				log.Printf("mDNS : relais %s", map[bool]string{true: "actif (pas de câble)", false: "en pause (câble branché)"}[!c])
			}
			actif.Store(!c)
			time.Sleep(10 * time.Second)
		}
	}()
	go versWifi(fd, cote, wifi, &actif)
	groupe := &syscall.SockaddrInet4{Port: 5353, Addr: [4]byte{224, 0, 0, 251}}
	buf := make([]byte, 9000)
	for {
		n, de, err := cote.ReadFrom(buf)
		if err != nil {
			log.Printf("mDNS : %v", err)
			return
		}
		m := buf[:n]
		// questions seulement (QR = 0) ; pas nos propres questions reposées, qui ressortent par le câble
		if !actif.Load() || n < 12 || m[2]&0x80 != 0 || binary.BigEndian.Uint16(m[4:]) == 0 {
			continue
		}
		if u, ok := de.(*net.UDPAddr); ok && u.IP.To4() != nil {
			if a := [4]byte(u.IP.To4()); a == wifi || adressesLocales()[a] {
				continue
			}
		}
		if *bavard {
			log.Printf("mDNS : question de %v reposée à mDNSResponder", de)
		}
		if err := questionApple(m, groupe); err != nil && *bavard {
			log.Printf("mDNS : question vers Apple : %v", err)
		}
	}
}

// versWifi : réponses et annonces de mDNSResponder (source = adresse locale) → Wi-Fi, adresses réécrites.
func versWifi(fd int, cote *gonet.UDPConn, wifi [4]byte, actif *atomic.Bool) {
	vers := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	buf := make([]byte, 9000)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			log.Printf("mDNS : lecture noyau : %v", err)
			return
		}
		a, ok := from.(*syscall.SockaddrInet4)
		if !ok || !actif.Load() || n < 12 || buf[2]&0x80 == 0 {
			continue
		}
		locales := adressesLocales()
		if !locales[a.Addr] {
			continue
		}
		rep := append([]byte(nil), buf[:n]...)
		if reecrire(rep, locales, wifi) {
			if _, err := cote.WriteTo(rep, vers); err != nil && *bavard {
				log.Printf("mDNS : envoi Wi-Fi : %v", err)
			} else if *bavard {
				log.Printf("mDNS : réponse d'Apple (%d octets) rediffusée sur le Wi-Fi", n)
			}
		}
	}
}
