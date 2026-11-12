// wg-tc : serveur WireGuard en espace utilisateur pour l'AirPort Time Capsule.
//
// Le noyau NetBSD 6 d'Apple n'a pas de pilote tun : la pile TCP/IP du tunnel
// est donc gVisor (netstack), dans le processus. Les connexions TCP et les flux
// UDP que les pairs ouvrent vers une adresse du réseau local (ou d'Internet si
// autorisé) sont relayés par de vrais sockets de la Time Capsule.
//
//	wg-tc -c /Volumes/dk2/.seconde-vie/wg/wg0.conf
//
// Fichier de configuration au format WireGuard habituel :
//
//	[Interface]
//	PrivateKey = …
//	ListenPort = 51820
//	Address = 10.66.0.1/24
//	# Relayer seulement vers ces réseaux (vide = tout)
//	RelayTo = 192.168.1.0/24
//	[Peer]
//	PublicKey = …
//	AllowedIPs = 10.66.0.2/32
//
// Ce programme doit être compilé avec le Go corrigé pour NetBSD 6
// (analyse/go-netbsd6-timecapsule.patch).
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const mtu = 1420

var trace bool

type config struct {
	uapi     strings.Builder
	adresses []netip.Addr
	relais   []netip.Prefix
}

func cle(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("clé invalide")
	}
	return hex.EncodeToString(b), nil
}

func lireConfig(chemin string) (*config, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c := &config{}
	section := ""
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		ligne := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(ligne, '#'); i >= 0 {
			ligne = strings.TrimSpace(ligne[:i])
		}
		if ligne == "" {
			continue
		}
		if strings.HasPrefix(ligne, "[") {
			section = strings.ToLower(strings.Trim(ligne, "[]"))
			if section == "peer" {
				c.uapi.WriteString("") // séparation logique
			}
			continue
		}
		k, v, ok := strings.Cut(ligne, "=")
		if !ok {
			return nil, fmt.Errorf("ligne %d : « clé = valeur » attendu", n)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section + "." + k {
		case "interface.privatekey":
			h, err := cle(v)
			if err != nil {
				return nil, fmt.Errorf("ligne %d : %w", n, err)
			}
			fmt.Fprintf(&c.uapi, "private_key=%s\n", h)
		case "interface.listenport":
			fmt.Fprintf(&c.uapi, "listen_port=%s\n", v)
		case "interface.address":
			for _, a := range strings.Split(v, ",") {
				p, err := netip.ParsePrefix(strings.TrimSpace(a))
				if err != nil {
					return nil, fmt.Errorf("ligne %d : %w", n, err)
				}
				c.adresses = append(c.adresses, p.Addr())
			}
		case "interface.relayto":
			for _, a := range strings.Split(v, ",") {
				p, err := netip.ParsePrefix(strings.TrimSpace(a))
				if err != nil {
					return nil, fmt.Errorf("ligne %d : %w", n, err)
				}
				c.relais = append(c.relais, p)
			}
		case "peer.publickey":
			h, err := cle(v)
			if err != nil {
				return nil, fmt.Errorf("ligne %d : %w", n, err)
			}
			fmt.Fprintf(&c.uapi, "public_key=%s\n", h)
		case "peer.presharedkey":
			h, err := cle(v)
			if err != nil {
				return nil, fmt.Errorf("ligne %d : %w", n, err)
			}
			fmt.Fprintf(&c.uapi, "preshared_key=%s\n", h)
		case "peer.allowedips":
			for _, a := range strings.Split(v, ",") {
				fmt.Fprintf(&c.uapi, "allowed_ip=%s\n", strings.TrimSpace(a))
			}
		case "peer.endpoint":
			fmt.Fprintf(&c.uapi, "endpoint=%s\n", v)
		case "peer.persistentkeepalive":
			fmt.Fprintf(&c.uapi, "persistent_keepalive_interval=%s\n", v)
		default:
			return nil, fmt.Errorf("ligne %d : clé inconnue %q dans [%s]", n, k, section)
		}
	}
	if len(c.adresses) == 0 {
		return nil, errors.New("Address manquante dans [Interface]")
	}
	return c, sc.Err()
}

func (c *config) autorise(a netip.Addr) bool {
	if len(c.relais) == 0 {
		return true
	}
	for _, p := range c.relais {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func versAddr(a tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return ip.Unmap()
}

// relaisTCP : chaque connexion ouverte par un pair est rejouée vers la vraie destination.
func relaisTCP(s *stack.Stack, c *config) {
	f := tcp.NewForwarder(s, 0, 64, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := versAddr(id.LocalAddress)
		if !c.autorise(dst) {
			r.Complete(true)
			return
		}
		cible := net.JoinHostPort(dst.String(), strconv.Itoa(int(id.LocalPort)))
		dehors, err := net.DialTimeout("tcp", cible, 5*time.Second)
		if trace {
			log.Printf("tcp %v:%d -> %s : %v", versAddr(id.RemoteAddress), id.RemotePort, cible, err)
		}
		if err != nil {
			r.Complete(true) // RST vers le pair
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
		dedans := gonet.NewTCPConn(&wq, ep)
		go copier(dedans, dehors)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)
}

func copier(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	sens := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go sens(a, b)
	go sens(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// relaisUDP : un socket réel par flux (pair, port) ; fermé après 60 s sans trafic.
func relaisUDP(s *stack.Stack, c *config) {
	f := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		dst := versAddr(id.LocalAddress)
		if !c.autorise(dst) {
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return
		}
		dedans := gonet.NewUDPConn(&wq, ep)
		dehors, err := net.Dial("udp", net.JoinHostPort(dst.String(), strconv.Itoa(int(id.LocalPort))))
		if err != nil {
			dedans.Close()
			return
		}
		go func() {
			defer dedans.Close()
			defer dehors.Close()
			buf := make([]byte, mtu)
			go func() {
				b := make([]byte, mtu)
				for {
					dehors.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := dehors.Read(b)
					if err != nil {
						dedans.Close()
						return
					}
					dedans.Write(b[:n])
				}
			}()
			for {
				dedans.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, err := dedans.Read(buf)
				if err != nil {
					return
				}
				dehors.Write(buf[:n])
			}
		}()
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, f.HandlePacket)
}

func main() {
	chemin := flag.String("c", "/Volumes/dk2/.seconde-vie/wg/wg0.conf", "fichier de configuration")
	memoire := flag.Int64("memoire", 20, "limite mémoire visée en Mo (ramasse-miettes plus actif au-delà)")
	verbeux := flag.Bool("v", false, "journal WireGuard détaillé")
	flag.Parse()
	trace = *verbeux
	debug.SetMemoryLimit(*memoire << 20)
	debug.SetGCPercent(50)

	c, err := lireConfig(*chemin)
	if err != nil {
		log.Fatalf("configuration : %v", err)
	}
	tdev, s, err := creerNetTUN(c.adresses, nil, mtu)
	if err != nil {
		log.Fatal(err)
	}
	// La pile accepte les paquets destinés à n'importe quelle adresse (relais)
	// et répond en leur nom.
	if e := s.SetPromiscuousMode(1, true); e != nil {
		log.Printf("SetPromiscuousMode : %v", e)
	}
	if e := s.SetSpoofing(1, true); e != nil {
		log.Printf("SetSpoofing : %v", e)
	}
	if trace {
		go func() {
			for range time.Tick(10 * time.Second) {
				st := s.Stats()
				log.Printf("stats ip: reçus=%d valides=%d désactivé=%d dest-inv=%d src-inv=%d malformés=%d prerouting=%d input=%d livrés=%d | tcp: segments=%d | ipv4: %+v",
					st.IP.PacketsReceived.Value(), st.IP.ValidPacketsReceived.Value(), st.IP.DisabledPacketsReceived.Value(),
					st.IP.InvalidDestinationAddressesReceived.Value(), st.IP.InvalidSourceAddressesReceived.Value(),
					st.IP.MalformedPacketsReceived.Value(), st.IP.IPTablesPreroutingDropped.Value(), st.IP.IPTablesInputDropped.Value(),
					st.IP.PacketsDelivered.Value(), st.TCP.ValidSegmentsReceived.Value(), st.IP.Forwarding)
			}
		}()
	}
	petit := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 32 << 10, Max: 128 << 10}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &petit)
	envoi := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 32 << 10, Max: 128 << 10}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &envoi)
	relaisTCP(s, c)
	relaisUDP(s, c)

	niveau := device.LogLevelError
	if *verbeux {
		niveau = device.LogLevelVerbose
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(niveau, "wg-tc: "))
	if err := dev.IpcSet(c.uapi.String()); err != nil {
		log.Fatalf("configuration WireGuard : %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal(err)
	}
	log.Printf("wg-tc prêt : %v, relais vers %v", c.adresses, c.relais)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	dev.Close()
}
