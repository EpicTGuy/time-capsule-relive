// tc-pont : rend la Time Capsule joignable par le Wi-Fi d'une box ou d'un routeur quelconque.
//
// Le noyau d'Apple (NetBSD 6) refuse toute adresse IPv4 sur l'interface Wi-Fi client (wlan1) : seuls les
// ponts en acceptent, et un pont prend une adresse MAC au hasard que le point d'accès rejette (une station
// Wi-Fi ordinaire ne peut parler qu'avec sa propre MAC). Ni tun, ni tap, ni « proxy STA » dans ce noyau.
// tc-pont porte donc sa propre pile TCP/IP (gVisor netstack) sur wlan1, par BPF, avec la MAC de la radio
// et l'adresse obtenue par tc-dhcp ; les connexions TCP entrantes sur les ports autorisés sont relayées
// vers les services locaux de la Time Capsule (SMB, SSH, ReLive…). Le ping est servi par la pile ; Bonjour
// est relayé (mdns.go) pour que le Finder et Time Machine la trouvent.
//
//	tc-pont -i wlan1 -mac 02:00:00:… -ip 192.168.1.188 -masque 255.255.255.0 -passerelle 192.168.1.1 \
//	        [-ports 22,80,139,443,445,5009] [-local 127.0.0.1] [-lan wlan0 [-lan-cable bcmeth0] -lan-mac …] [-v]
//
// wlan1 doit être retiré de bridge0 (ACPd l'y met en client simple) : sinon le noyau ponte aussi le Wi-Fi.
//
// À compiler avec le Go corrigé pour NetBSD 6 (outils/construire-tc.sh).
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const mtu = 1500

var (
	bavard = flag.Bool("v", false, "journal de chaque connexion")
	mdns   = flag.Bool("mdns", true, "relayer Bonjour (annonces SMB, Time Machine) vers le Wi-Fi")
)

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return fmt.Errorf("ioctl 0x%x : %w", req, e)
	}
	return nil
}

// filtreClient : côté Wi-Fi client, trames destinées à notre MAC, ARP diffusés, multicast mDNS.
func filtreClient(mac net.HardwareAddr) []syscall.BpfInsn {
	haut := binary.BigEndian.Uint32(mac[0:4])
	bas := uint32(binary.BigEndian.Uint16(mac[4:6]))
	return []syscall.BpfInsn{
		{Code: 0x20, K: 0},                        // 0  ld [0]
		{Code: 0x15, Jt: 0, Jf: 2, K: haut},       // 1  MAC destination = la nôtre ?
		{Code: 0x28, K: 4},                        // 2  ldh [4]
		{Code: 0x15, Jt: 7, Jf: 0, K: bas},        // 3    oui → tout
		{Code: 0x20, K: 0},                        // 4  ld [0]
		{Code: 0x15, Jt: 0, Jf: 2, K: 0xffffffff}, // 5  diffusion ?
		{Code: 0x28, K: 12},                       // 6    ldh [12]
		{Code: 0x15, Jt: 3, Jf: 4, K: 0x806},      // 7    ARP seulement
		{Code: 0x15, Jt: 0, Jf: 3, K: 0x01005e00}, // 8  multicast mDNS 01:00:5e:00:00:fb ?
		{Code: 0x28, K: 4},                        // 9    ldh [4]
		{Code: 0x15, Jt: 0, Jf: 1, K: 0x00fb},     // 10
		{Code: 0x06, K: 0xffff},                   // 11 accepter
		{Code: 0x06, K: 0},                        // 12 refuser
	}
}

// filtreCable : côté appareils (Wi-Fi de la Time Capsule, câble), les trames pour la MAC de bridge0 et les ARP
// diffusés. Pas les autres : le pont du noyau fait passer le trafic entre appareils, qui ne nous regarde pas.
func filtreCable(mac net.HardwareAddr) []syscall.BpfInsn {
	return []syscall.BpfInsn{
		{Code: 0x20, K: 0}, // 0  ld [0] : 4 premiers octets de la MAC destination
		{Code: 0x15, Jt: 0, Jf: 2, K: binary.BigEndian.Uint32(mac[0:4])}, // 1
		{Code: 0x28, K: 4}, // 2    ldh [4]
		{Code: 0x15, Jt: 3, Jf: 4, K: uint32(binary.BigEndian.Uint16(mac[4:6]))}, // 3    notre MAC
		{Code: 0x15, Jt: 0, Jf: 3, K: 0xffffffff},                                // 4  diffusion ?
		{Code: 0x28, K: 12},                  // 5    ldh [12]
		{Code: 0x15, Jt: 0, Jf: 1, K: 0x806}, // 6    ARP seulement
		{Code: 0x06, K: 0xffff},              // 7  accepter
		{Code: 0x06, K: 0},                   // 8  refuser
	}
}

// ouvrirBPF : périphérique BPF sur l'interface, avec le filtre donné ; nos propres envois ne sont pas relus.
func ouvrirBPF(nom string, filtre []syscall.BpfInsn) (int, error) {
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
	prog := syscall.BpfProgram{Len: uint32(len(filtre)), Insns: &filtre[0]}
	var ifr [144]byte // struct ifreq de NetBSD 6 (16 + sockaddr_storage)
	copy(ifr[:], nom)
	un, zero := 1, 0
	for _, io := range []struct {
		req uintptr
		arg unsafe.Pointer
	}{
		{syscall.BIOCSETIF, unsafe.Pointer(&ifr[0])},
		{syscall.BIOCIMMEDIATE, unsafe.Pointer(&un)},
		{syscall.BIOCSHDRCMPLT, unsafe.Pointer(&un)},
		{syscall.BIOCSSEESENT, unsafe.Pointer(&zero)},
		{syscall.BIOCSETF, unsafe.Pointer(&prog)},
	} {
		if err := ioctl(fd, io.req, io.arg); err != nil {
			syscall.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// doublons : le pilote Broadcom remet chaque trame reçue plusieurs fois sur wlan1 (des dizaines de copies
// par ping, mesurées le 10/11/2026) ; une trame identique à une autre reçue il y a moins de 150 ms est
// une copie. Une vraie retransmission TCP arrive bien plus tard (délai minimal 200 ms).
type doublons struct {
	vus map[uint64]time.Time
	nb  int
}

func (d *doublons) copie(trame []byte) bool {
	h := fnv.New64a() // en-têtes (Ethernet, IP, TCP : numéros de séquence compris) et longueur : assez pour distinguer
	h.Write(trame[:min(len(trame), 64)])
	k := h.Sum64() ^ uint64(len(trame))
	now := time.Now()
	if t, ok := d.vus[k]; ok && now.Sub(t) < 150*time.Millisecond {
		return true
	}
	d.vus[k] = now
	if d.nb++; d.nb%1024 == 0 {
		for k, t := range d.vus {
			if now.Sub(t) > time.Second {
				delete(d.vus, k)
			}
		}
	}
	return false
}

// entrant : tampons BPF → trames Ethernet → pile (en-tête bpf_hdr : caplen à 8, hdrlen à 16).
// garder (facultatif) écarte des trames avant la pile.
// (Lecture bloquante. Essayé le 11/11/2026 : BPF non bloquant lu par l'ordonnanceur de Go (os.File, kqueue) ;
// tc-pont ne relayait plus rien, cause probable : pas de kqueue pour BPF sur ce NetBSD 6.)
func entrant(fd int, ep *channel.Endpoint, garder func([]byte) bool) {
	d := &doublons{vus: map[uint64]time.Time{}}
	var blen int32
	ioctl(fd, syscall.BIOCGBLEN, unsafe.Pointer(&blen))
	if blen <= 0 {
		blen = 4096
	}
	buf := make([]byte, blen)
	for {
		n, err := syscall.Read(fd, buf)
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
			trame := buf[p+hdrlen : p+hdrlen+caplen]
			p += (hdrlen + caplen + 3) &^ 3
			if d.copie(trame) || (garder != nil && !garder(trame)) {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append([]byte(nil), trame...)),
			})
			ep.InjectInbound(0, pkt) // l'enveloppe ethernet lit l'en-tête et choisit le protocole
			pkt.DecRef()
		}
	}
}

// sortant : trames complètes (en-tête Ethernet ajouté par l'enveloppe) → BPF.
func sortant(fd int, ep *channel.Endpoint) {
	for {
		pkt := ep.ReadContext(context.Background())
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		if _, err := syscall.Write(fd, v.AsSlice()); err != nil && *bavard {
			log.Printf("envoi : %v", err)
		}
		v.Release()
		pkt.DecRef()
	}
}

func relaisTCP(s *stack.Stack, ports map[uint16]bool, local string) {
	f := tcp.NewForwarder(s, 0, 64, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		if !ports[id.LocalPort] {
			r.Complete(true) // RST : port non relayé
			return
		}
		cible := net.JoinHostPort(local, strconv.Itoa(int(id.LocalPort)))
		dehors, err := net.DialTimeout("tcp", cible, 5*time.Second)
		if *bavard {
			log.Printf("tcp %v:%d -> %s : %v", id.RemoteAddress, id.RemotePort, cible, err)
		}
		if err != nil {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			dehors.Close()
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetKeepAlive(true)
		go copier(gonet.NewTCPConn(&wq, ep), dehors)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)
}

func copier(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	var n [2]int64
	var e [2]error
	sens := func(i int, dst, src net.Conn) {
		defer wg.Done()
		n[i], e[i] = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go sens(0, a, b)
	go sens(1, b, a)
	wg.Wait()
	if *bavard {
		log.Printf("fin %v ↔ %v : %d octets vers %v (%v), %d vers %v (%v)", a.RemoteAddr(), b.RemoteAddr(),
			n[0], a.RemoteAddr(), e[0], n[1], b.RemoteAddr(), e[1])
	}
	a.Close()
	b.Close()
}

func main() {
	nomIf := flag.String("i", "wlan1", "interface Wi-Fi client")
	adresse := flag.String("mac", "", "adresse MAC de l'interface (ifconfig … ether)")
	ipFlag := flag.String("ip", "", "adresse obtenue par DHCP, ex. 192.168.1.188")
	masque := flag.String("masque", "255.255.255.0", "masque du réseau")
	gw := flag.String("passerelle", "", "routeur (route par défaut de la pile)")
	portsFlag := flag.String("ports", "22,80,139,443,445,5009", "ports TCP relayés vers les services locaux")
	local := flag.String("local", "127.0.0.1", "adresse locale des services")
	lanIf := flag.String("lan", "", "mode relais : Wi-Fi de la Time Capsule à partager, ex. wlan0 ou wlan2,wlan3")
	lanMac := flag.String("lan-mac", "", "mode relais : MAC de bridge0 (celle du routeur 10.42.42.1, tenu par le noyau)")
	lanIP := flag.String("lan-ip", "10.42.42.0/24", "mode relais : réseau partagé")
	lanCable := flag.String("lan-cable", "", "mode relais : partager aussi le câble Ethernet, ex. bcmeth0")
	dnsAmont := flag.String("dns-amont", "", "mode relais : serveur DNS du réseau Wi-Fi (défaut : la passerelle)")
	profil := flag.String("profil", "", "diagnostic : profil processeur des 30 premières secondes dans ce fichier")
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime)
	// Un seul cœur, mais plusieurs lectures BPF bloquantes : avec un seul P, chacune le garde pendant l'appel
	// système et le reste du programme attend que sysmon le reprenne (38 ms par paquet relayé, mesuré le
	// 11/11/2026). Ramasse-miettes moins fréquent : le processeur est la limite.
	runtime.GOMAXPROCS(4)
	debug.SetGCPercent(200)
	if *profil != "" {
		if f, err := os.Create(*profil); err == nil {
			pprof.StartCPUProfile(f)
			time.AfterFunc(30*time.Second, func() { pprof.StopCPUProfile(); f.Close() })
		}
	}

	mac, err := net.ParseMAC(*adresse)
	if err != nil || len(mac) != 6 {
		log.Fatalf("-mac invalide : %q", *adresse)
	}
	a, err := netip.ParseAddr(*ipFlag)
	m := net.ParseIP(*masque).To4()
	if err != nil || !a.Is4() || m == nil {
		log.Fatalf("-ip ou -masque invalide : %q %q", *ipFlag, *masque)
	}
	longueur, _ := net.IPMask(m).Size()
	pref := netip.PrefixFrom(a, longueur)
	ports := map[uint16]bool{} // vide (-ports=) : réseau qui n'est pas de confiance, rien n'est relayé
	for _, p := range strings.FieldsFunc(*portsFlag, func(r rune) bool { return r == ',' }) {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n <= 0 || n > 65535 {
			log.Fatalf("port invalide : %q", p)
		}
		ports[uint16(n)] = true
	}

	fd, err := ouvrirBPF(*nomIf, filtreClient(mac))
	if err != nil {
		log.Fatal(err)
	}
	ch := canal(mac)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	if terr := s.CreateNIC(1, ethernet.New(ch)); terr != nil {
		log.Fatalf("CreateNIC : %v", terr)
	}
	adr := tcpip.AddrFrom4(pref.Addr().As4())
	if terr := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: adr, PrefixLen: pref.Bits()},
	}, stack.AddressProperties{}); terr != nil {
		log.Fatalf("AddProtocolAddress : %v", terr)
	}
	sousReseau := tcpip.AddressWithPrefix{Address: adr, PrefixLen: pref.Bits()}.Subnet()
	routes := []tcpip.Route{{Destination: sousReseau, NIC: 1}}
	if *gw != "" {
		g, err := netip.ParseAddr(*gw)
		if err != nil || !g.Is4() {
			log.Fatalf("-passerelle invalide : %q", *gw)
		}
		routes = append(routes, tcpip.Route{Destination: header0(), Gateway: tcpip.AddrFrom4(g.As4()), NIC: 1})
	}
	s.SetRouteTable(routes)
	if len(ports) > 0 {
		relaisTCP(s, ports, *local)
	}
	if *mdns {
		go relaisMDNS(s, pref.Addr().As4())
	}
	s.SetPortRange(16000, natPremier-1) // les ports au-delà sont ceux de la traduction d'adresses
	var garder func([]byte) bool
	if *lanIf != "" {
		lm, err1 := net.ParseMAC(*lanMac)
		lp, err2 := netip.ParsePrefix(*lanIP)
		g, err3 := netip.ParseAddr(*gw)
		amont := *dnsAmont
		if amont == "" {
			amont = *gw
		}
		da, err4 := netip.ParseAddr(amont)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			log.Fatalf("mode relais : -lan-mac, -lan-ip, -passerelle ou -dns-amont invalide (%v %v %v %v)",
				err1, err2, err3, err4)
		}
		go relaisDNS(s, lp.Masked().Addr().Next(), da)
		n := nouveauNAT(pref.Addr().As4(), lp.Masked(), mac, lm, fd)
		go n.suivreRouteur(s, tcpip.AddrFrom4(g.As4()), adr)
		interfaces := strings.Split(*lanIf, ",")
		if *lanCable != "" {
			interfaces = append(interfaces, *lanCable)
		}
		partager(n, interfaces)
		garder = func(t []byte) bool { return !n.entrant(t) }
	}
	go entrant(fd, ch, garder)
	if len(ports) > 0 {
		log.Printf("joignable par le Wi-Fi (%s) en %s, ports %s → %s", *nomIf, pref, *portsFlag, *local)
	} else {
		log.Printf("Wi-Fi (%s) en %s : réseau qui n'est pas de confiance, services de la Time Capsule non relayés",
			*nomIf, pref)
	}
	sortant(fd, ch)
}

// canal : lien entre une pile gVisor et un descripteur BPF. Sommes de contrôle reçues non revérifiées : le Wi-Fi
// et l'Ethernet contrôlent déjà chaque trame (FCS), et le processeur est la limite du débit.
func canal(mac net.HardwareAddr) *channel.Endpoint {
	ch := channel.New(512, mtu, tcpip.LinkAddress(mac))
	ch.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	return ch
}

// header0 : 0.0.0.0/0 (route par défaut).
func header0() tcpip.Subnet {
	s, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	return s
}
