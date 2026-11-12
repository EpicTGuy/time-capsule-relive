// Essai : un binaire Go netbsd/arm tourne-t-il sur le NetBSD 6 d'Apple ?
package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

func main() {
	fmt.Println("go", runtime.Version(), runtime.GOOS, runtime.GOARCH, "cpus", runtime.NumCPU())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); time.Sleep(50 * time.Millisecond) }()
	}
	wg.Wait()
	fmt.Println("goroutines ok")
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		fmt.Println("aléa ERREUR", err)
		os.Exit(1)
	}
	fmt.Printf("aléa ok %x\n", b[:4])
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		fmt.Println("udp ERREUR", err)
		os.Exit(1)
	}
	fmt.Println("udp ok", c.LocalAddr())
	c.Close()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("mémoire Go %d Ko\n", m.Sys/1024)
}

func init() {
	// Charge : boucles serrées sur plusieurs goroutines pendant 3 s, pour
	// déclencher la préemption asynchrone (signal SIGURG) et le ramasse-miettes.
	go func() {}()
	fin := time.Now().Add(3 * time.Second)
	var wg sync.WaitGroup
	total := make([]int, 4)
	for i := range total {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for time.Now().Before(fin) {
				for k := 0; k < 1_000_000; k++ {
					total[i] += k & 7
				}
				_ = make([]byte, 64<<10)
			}
		}(i)
	}
	wg.Wait()
	fmt.Println("charge ok", total[0] > 0)
}
