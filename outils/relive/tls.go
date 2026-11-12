package main

// HTTPS pour ReLive : certificat auto-signé créé au premier démarrage et gardé
// dans le dossier de travail (cle.pem en 600). Les navigateurs récents essaient
// HTTPS d'abord ; sans lui, ils échouent au lieu de revenir à HTTP.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func certificat(dossier string) (tls.Certificate, error) {
	cert, cle := filepath.Join(dossier, "relive-cert.pem"), filepath.Join(dossier, "relive-cle.pem")
	if c, err := tls.LoadX509KeyPair(cert, cle); err == nil {
		return c, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serie, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	nom, _ := os.Hostname()
	modele := x509.Certificate{
		SerialNumber:          serie,
		Subject:               pkix.Name{CommonName: "ReLive (Time Capsule)", Organization: []string{"Time Capsule ReLive"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{nom, nom + ".local", "localhost"},
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ip, _, err := net.ParseCIDR(a.String()); err == nil && !ip.IsLoopback() {
				modele.IPAddresses = append(modele.IPAddresses, ip)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &modele, &modele, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	octets, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(cle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: octets}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(cert, cle)
}
