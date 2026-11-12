package main

import (
	"diag5/sous"
	"fmt"
	"text/template"
	"os"
)

var local = []any{new(int), "y"}

func main() {
	fmt.Printf("main.local: %v %v\n", local[0] != nil, local[1])
	fmt.Printf("sous.Table: %v %v %v | Calcule %d | ParInit %d\n", sous.Table[0] != nil, sous.Table[1], sous.Table[2], sous.Calcule, sous.ParInit)
	t, err := template.New("t").Parse("bonjour {{.}} {{len .}}\n")
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	if err := t.Execute(os.Stdout, "monde"); err != nil {
		fmt.Println("exec:", err)
	}
}
