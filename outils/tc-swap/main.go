// tc-swap : active ou retire un fichier d'échange (swap) sur la Time Capsule.
// Le crunchprog d'Apple n'a pas swapctl ; on appelle directement swapctl(2).
//
//	tc-swap liste
//	tc-swap creer <fichier> <Mo>   (fichier plein de zéros, droits 600)
//	tc-swap on <fichier>
//	tc-swap off <fichier>
//
// À compiler avec le Go corrigé pour NetBSD 6 (analyse/go-netbsd6-timecapsule.patch).
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	sysSwapctl = 271 // NetBSD sys/syscall.h : SYS_swapctl
	swapOn     = 1
	swapOff    = 2
	swapNswap  = 3
	swapStats  = 9 // SWAP_STATS (NetBSD 5+, struct swapent avec se_dev 64 bits)
)

func swapctl(cmd int, arg unsafe.Pointer, misc int) (int, error) {
	r, _, e := syscall.Syscall(sysSwapctl, uintptr(cmd), uintptr(arg), uintptr(misc))
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

func chemin(p string) unsafe.Pointer {
	b, _ := syscall.BytePtrFromString(p)
	return unsafe.Pointer(b)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage : tc-swap liste | creer <fichier> <Mo> | on <fichier> | off <fichier>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "liste":
		n, err := swapctl(swapNswap, nil, 0)
		fmt.Println("zones d'échange actives :", n, err)
	case "creer":
		mo, _ := strconv.Atoi(os.Args[3])
		f, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		zero := make([]byte, 1<<20)
		for i := 0; i < mo; i++ {
			if _, err := f.Write(zero); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		f.Sync()
		f.Close()
		fmt.Println("créé", os.Args[2], mo, "Mo")
	case "on":
		_, err := swapctl(swapOn, chemin(os.Args[2]), 0)
		fmt.Println("swap on :", err)
		if err != nil {
			os.Exit(1)
		}
	case "off":
		_, err := swapctl(swapOff, chemin(os.Args[2]), 0)
		fmt.Println("swap off :", err)
		if err != nil {
			os.Exit(1)
		}
	}
}
