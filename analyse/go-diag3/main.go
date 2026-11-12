package main

import (
	"fmt"
	. "math"
)

var vfpowSC = [][2]float64{
	{Inf(-1), -Pi},
	{Inf(-1), -3},
	{Inf(-1), Copysign(0, -1)},
	{Inf(-1), 0},
	{Inf(-1), 1},
	{Inf(-1), 3},
	{Inf(-1), Pi},
	{Inf(-1), 0.5},
	{Inf(-1), NaN()},

	{-Pi, Inf(-1)},
	{-Pi, -Pi},
	{-Pi, Copysign(0, -1)},
	{-Pi, 0},
	{-Pi, 1},
	{-Pi, Pi},
	{-Pi, Inf(1)},
	{-Pi, NaN()},

	{-1, Inf(-1)},
	{-1, Inf(1)},
	{-1, NaN()},
	{-0.5, Inf(-1)},
	{-0.5, Inf(1)},
	{Copysign(0, -1), Inf(-1)},
	{Copysign(0, -1), -Pi},
	{Copysign(0, -1), -0.5},
	{Copysign(0, -1), -3},
	{Copysign(0, -1), 3},
	{Copysign(0, -1), Pi},
	{Copysign(0, -1), 0.5},
	{Copysign(0, -1), Inf(1)},

	{0, Inf(-1)},
	{0, -Pi},
	{0, -3},
	{0, Copysign(0, -1)},
	{0, 0},
	{0, 3},
	{0, Pi},
	{0, Inf(1)},
	{0, NaN()},

	{0.5, Inf(-1)},
	{0.5, Inf(1)},
	{1, Inf(-1)},
	{1, Inf(1)},
	{1, NaN()},

	{Pi, Inf(-1)},
	{Pi, Copysign(0, -1)},
	{Pi, 0},
	{Pi, 1},
	{Pi, Inf(1)},
	{Pi, NaN()},
	{Inf(1), -Pi},
	{Inf(1), Copysign(0, -1)},
	{Inf(1), 0},
	{Inf(1), 1},
	{Inf(1), Pi},
	{Inf(1), NaN()},
	{NaN(), -Pi},
	{NaN(), Copysign(0, -1)},
	{NaN(), 0},
	{NaN(), 1},
	{NaN(), Pi},
	{NaN(), NaN()},

	// Issue #7394 overflow checks
	{2, float64(1 << 32)},
	{2, -float64(1 << 32)},
	{-2, float64(1<<32 + 1)},
	{0.5, float64(1 << 45)},
	{0.5, -float64(1 << 45)},
	{Nextafter(1, 2), float64(1 << 63)},
	{Nextafter(1, -2), float64(1 << 63)},
	{Nextafter(-1, 2), float64(1 << 63)},
	{Nextafter(-1, -2), float64(1 << 63)},

	// Issue #57465
	{Copysign(0, -1), 1e19},
	{Copysign(0, -1), -1e19},
	{Copysign(0, -1), 1<<53 - 1},
	{Copysign(0, -1), -(1<<53 - 1)},
}
var powSC = []float64{
	0,               // pow(-Inf, -Pi)
	Copysign(0, -1), // pow(-Inf, -3)
	1,               // pow(-Inf, -0)
	1,               // pow(-Inf, +0)
	Inf(-1),         // pow(-Inf, 1)
	Inf(-1),         // pow(-Inf, 3)
	Inf(1),          // pow(-Inf, Pi)
	Inf(1),          // pow(-Inf, 0.5)
	NaN(),           // pow(-Inf, NaN)
	0,               // pow(-Pi, -Inf)
	NaN(),           // pow(-Pi, -Pi)
	1,               // pow(-Pi, -0)
	1,               // pow(-Pi, +0)
	-Pi,             // pow(-Pi, 1)
	NaN(),           // pow(-Pi, Pi)
	Inf(1),          // pow(-Pi, +Inf)
	NaN(),           // pow(-Pi, NaN)
	1,               // pow(-1, -Inf) IEEE 754-2008
	1,               // pow(-1, +Inf) IEEE 754-2008
	NaN(),           // pow(-1, NaN)
	Inf(1),          // pow(-1/2, -Inf)
	0,               // pow(-1/2, +Inf)
	Inf(1),          // pow(-0, -Inf)
	Inf(1),          // pow(-0, -Pi)
	Inf(1),          // pow(-0, -0.5)
	Inf(-1),         // pow(-0, -3) IEEE 754-2008
	Copysign(0, -1), // pow(-0, 3) IEEE 754-2008
	0,               // pow(-0, +Pi)
	0,               // pow(-0, 0.5)
	0,               // pow(-0, +Inf)
	Inf(1),          // pow(+0, -Inf)
	Inf(1),          // pow(+0, -Pi)
	Inf(1),          // pow(+0, -3)
	1,               // pow(+0, -0)
	1,               // pow(+0, +0)
	0,               // pow(+0, 3)
	0,               // pow(+0, +Pi)
	0,               // pow(+0, +Inf)
	NaN(),           // pow(+0, NaN)
	Inf(1),          // pow(1/2, -Inf)
	0,               // pow(1/2, +Inf)
	1,               // pow(1, -Inf) IEEE 754-2008
	1,               // pow(1, +Inf) IEEE 754-2008
	1,               // pow(1, NaN) IEEE 754-2008
	0,               // pow(+Pi, -Inf)
	1,               // pow(+Pi, -0)
	1,               // pow(+Pi, +0)
	Pi,              // pow(+Pi, 1)
	Inf(1),          // pow(+Pi, +Inf)
	NaN(),           // pow(+Pi, NaN)
	0,               // pow(+Inf, -Pi)
	1,               // pow(+Inf, -0)
	1,               // pow(+Inf, +0)
	Inf(1),          // pow(+Inf, 1)
	Inf(1),          // pow(+Inf, Pi)
	NaN(),           // pow(+Inf, NaN)
	NaN(),           // pow(NaN, -Pi)
	1,               // pow(NaN, -0)
	1,               // pow(NaN, +0)
	NaN(),           // pow(NaN, 1)
	NaN(),           // pow(NaN, +Pi)
	NaN(),           // pow(NaN, NaN)

	// Issue #7394 overflow checks
	Inf(1),  // pow(2, float64(1 << 32))
	0,       // pow(2, -float64(1 << 32))
	Inf(-1), // pow(-2, float64(1<<32 + 1))
	0,       // pow(1/2, float64(1 << 45))
	Inf(1),  // pow(1/2, -float64(1 << 45))
	Inf(1),  // pow(Nextafter(1, 2), float64(1 << 63))
	0,       // pow(Nextafter(1, -2), float64(1 << 63))
	0,       // pow(Nextafter(-1, 2), float64(1 << 63))
	Inf(1),  // pow(Nextafter(-1, -2), float64(1 << 63))

	// Issue #57465
	0,               // pow(-0, 1e19)
	Inf(1),          // pow(-0, -1e19)
	Copysign(0, -1), // pow(-0, 1<<53 -1)
	Inf(-1),         // pow(-0, -(1<<53 -1))
}
func alike(a, b float64) bool {
	switch {
	case IsNaN(a) && IsNaN(b):
		return true
	case a == b:
		return Signbit(a) == Signbit(b)
	}
	return false
}

func main() {
	ko := 0
	for i := range vfpowSC {
		if f := Pow(vfpowSC[i][0], vfpowSC[i][1]); !alike(powSC[i], f) {
			if ko < 5 {
				fmt.Printf("Pow(%g, %g) = %g, want %g\n", vfpowSC[i][0], vfpowSC[i][1], f, powSC[i])
			}
			ko++
		}
	}
	fmt.Printf("%d cas, %d erreurs\n", len(vfpowSC), ko)
}
