package main

import (
	"fmt"
	"math"
	"reflect"
)

type paire struct {
	i any
	s string
}

var table = []paire{{new(int), "int"}, {new(int8), "int8"}, {new(float64), "f64"}}
var flottants = [][2]float64{{math.Inf(-1), -3}, {math.Copysign(0, -1), 1}, {0, -1}}

func main() {
	fmt.Println("inf", math.Inf(-1), "negzero", math.Copysign(0, -1), "signbit", math.Signbit(math.Copysign(0, -1)))
	fmt.Println("pow(-inf,-3)", math.Pow(math.Inf(-1), -3), "pow(0,-1)", math.Pow(0, -1))
	for _, f := range flottants {
		fmt.Printf("table %v %v -> %v\n", f[0], f[1], math.Pow(f[0], f[1]))
	}
	for _, p := range table {
		v := reflect.ValueOf(p.i)
		fmt.Println("reflect", p.s, v.Kind(), v.IsNil(), v.Elem().IsValid(), v.Elem().Kind())
	}
	x := new(int)
	v := reflect.ValueOf(x).Elem()
	v.SetInt(132)
	fmt.Println("set", *x)
	var i any = x
	fmt.Println("iface", i.(*int) == x, reflect.TypeOf(i))
}
