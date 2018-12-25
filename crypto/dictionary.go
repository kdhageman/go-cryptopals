package crypto

import (
	"math"
	"strings"
)

const (
	NonAlphabetic = 0.0696727022353
	Other         = 0.0
)

var (
	EnDict = map[int32]float64{
		'a': 0.0669431716653,
		'b': 0.0122296084394,
		'c': 0.0228034656022,
		'd': 0.0348609414831,
		'e': 0.104115607505,
		'f': 0.0182624447741,
		'g': 0.016516528824,
		'h': 0.0499512291084,
		'i': 0.0570988286789,
		'j': 0.00125410864023,
		'k': 0.00632792072066,
		'l': 0.0329920737055,
		'm': 0.0197214731268,
		'n': 0.0553201255748,
		'o': 0.0615332912565,
		'p': 0.0158116050132,
		'q': 0.000778694907335,
		'r': 0.0490741727391,
		's': 0.0518610808285,
		't': 0.0742301166403,
		'u': 0.0226067426782,
		'v': 0.0080164591513,
		'w': 0.0193444208559,
		'x': 0.00122951827474,
		'y': 0.0161804604956,
		'z': 0.000606562348872,
		' ': 0.110656644727,
	}
)

func emptyDict() map[int32]float64 {
	res := map[int32]float64{}
	for k := range EnDict {
		res[k] = 0.0
	}
	return res
}

func isNonAlphabetic(r rune) bool {
	return r >= 0x21 && r <= 0x40 ||
		r >= 0x5b && r <= 0x60
}

type counter struct {
	total         float64
	nonAlphabetic float64
	other         float64
}

func ChiSquared(s string) float64 {
	s = strings.ToLower(s)
	observations := emptyDict()
	c := counter{}
	for _, r := range s {
		if _, ok := EnDict[r]; ok {
			observations[r] += 1
		} else if isNonAlphabetic(r) {
			c.nonAlphabetic++
		} else {
			c.other++
		}
		c.total++
	}

	chi := 0.0
	for k := range EnDict { // [a-zA-Z]
		expected := EnDict[k] * c.total
		actual := observations[k]
		chi += math.Pow(expected-actual, 2)
	}
	chi += math.Pow(NonAlphabetic*c.total-c.nonAlphabetic, 2) // for non-alphabetic characters
	chi += math.Pow(Other*c.total-c.other, 2)                 // for remaining, nonsense characters

	return chi
}

func FindKey(b []byte) (byte, float64, []byte) {
	var pt []byte
	var key byte

	char := 0x00
	score := math.MaxFloat64
	for char != 0xff {
		curPt := XorSingle(b, byte(char))
		s := string(curPt)
		chi := ChiSquared(s)

		if chi < score {
			score = chi
			key = byte(char)
			pt = curPt
		}
		char += 0x01
	}

	return key, score, pt
}
