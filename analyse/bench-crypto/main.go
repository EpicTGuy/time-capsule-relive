// Mesure ChaCha20, Poly1305 et ChaCha20-Poly1305 (x/crypto) sur la Time Capsule,
// pour savoir où accélérer WireGuard.
package main

import (
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

func mesure(nom string, taille int, f func(b []byte)) {
	b := make([]byte, taille)
	n := 0
	debut := time.Now()
	for time.Since(debut) < 2*time.Second {
		f(b)
		n += taille
	}
	fmt.Printf("%-22s %7.1f Mo/s\n", nom, float64(n)/time.Since(debut).Seconds()/1e6)
}

func main() {
	cle := make([]byte, 32)
	nonce := make([]byte, 12)
	aead, _ := chacha20poly1305.New(cle)
	dst := make([]byte, 0, 1500)
	mesure("chacha20", 1420, func(b []byte) {
		c, _ := chacha20.NewUnauthenticatedCipher(cle, nonce)
		c.XORKeyStream(b, b)
	})
	var k [32]byte
	mesure("poly1305", 1420, func(b []byte) {
		var tag [16]byte
		poly1305.Sum(&tag, b, &k)
	})
	mesure("chacha20poly1305 seal", 1420, func(b []byte) {
		dst = aead.Seal(dst[:0], nonce, b, nil)
	})
}
