package crypto

import (
	"math"
	"strings"
)

const (
	NonAlphabetic    = 0.0696727022353
	NonAlphabeticSOS = 0.0
	Other            = 0.0
)

type param struct {
	dict          map[int32]float64
	nonAlphabetic float64
}

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

	EnDictSOS = map[int32]float64{
		'a': 0.0945723684,
		'b': 0.0472274436,
		'c': 0.0192081767,
		'd': 0.0184249687,
		'e': 0.0169956140,
		'f': 0.0286262531,
		'g': 0.0101229637,
		'h': 0.0911066729,
		'i': 0.1371788847,
		'j': 0.0069313910,
		'k': 0.0027999687,
		'l': 0.0139606830,
		'm': 0.0359492481,
		'n': 0.0257283835,
		'o': 0.0339716479,
		'p': 0.0202459273,
		'q': 0.0008027882,
		'r': 0.0130404135,
		's': 0.0631461466,
		't': 0.2335526316,
		'u': 0.0058544799,
		'v': 0.0027999687,
		'w': 0.0606986216,
		'x': 0.0000391604,
		'y': 0.0168193922,
		'z': 0.0001958020,
	}

	params = map[bool]param{
		false: {
			dict:          EnDict,
			nonAlphabetic: NonAlphabetic,
		},
		true: {
			dict:          EnDictSOS,
			nonAlphabetic: NonAlphabeticSOS,
		},
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

func ChiSquared(s string, sos bool) float64 {
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
	for k := range params[sos].dict { // [a-zA-Z]
		expected := params[sos].dict[k] * c.total
		actual := observations[k]
		chi += math.Pow(expected-actual, 2)
	}
	chi += math.Pow(params[sos].nonAlphabetic*c.total-c.nonAlphabetic, 2) // for non-alphabetic characters
	chi += math.Pow(Other*c.total-c.other, 2)                             // for remaining, nonsense characters

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
		chi := ChiSquared(s, false)

		if chi < score {
			score = chi
			key = byte(char)
			pt = curPt
		}
		char += 0x01
	}

	return key, score, pt
}
