package main

import "fmt"

func main() {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	premier, ko := -1, 0
	for i := 0; i < len(texte); i++ {
		if texte[i] != alphabet[(i*7+i/97)%36] {
			if premier < 0 {
				premier = i
			}
			ko++
		}
	}
	fmt.Printf("chaîne de %d octets : %d faux, premier faux à %d\n", len(texte), ko, premier)
}
