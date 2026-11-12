package sous

import "math"

var Table = []any{new(int), "x", math.Inf(-1)}
var Calcule = calcule()
var ParInit int

func calcule() int { return 42 }

func init() { ParInit = 7 }
