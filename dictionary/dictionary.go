package dictionary

import (
	"github.com/kdhageman/gocrypto/crypto"
	"math"
	"strings"
)

var (
	EnDict = map[int32]float64{
		'a': 0.0651738,
		'b': 0.0124248,
		'c': 0.0217339,
		'd': 0.0349835,
		'e': 0.1041442,
		'f': 0.0197881,
		'g': 0.0158610,
		'h': 0.0492888,
		'i': 0.0558094,
		'j': 0.0009033,
		'k': 0.0050529,
		'l': 0.0331490,
		'm': 0.0202124,
		'n': 0.0564513,
		'o': 0.0596302,
		'p': 0.0137645,
		'q': 0.0008606,
		'r': 0.0497563,
		's': 0.0515760,
		't': 0.0729357,
		'u': 0.0225134,
		'v': 0.0082903,
		'w': 0.0171272,
		'x': 0.0013692,
		'y': 0.0145984,
		'z': 0.0007836,
		' ': 0.1918182,
	}
)

func emptyDict() map[int32]float64 {
	res := map[int32]float64{}
	for k := range EnDict {
		res[k] = 0.0
	}
	return res
}

func ChiSquared(s string) float64 {
	s = strings.ToLower(s)
	observations := emptyDict()
	nRunes := 0.0
	for _, r := range s {
		if _, ok := EnDict[r]; ok {
			observations[r] += 1
		}
		nRunes++
	}

	chi := 0.0
	for k := range EnDict {
		expected := EnDict[k] * nRunes
		actual := observations[k]
		chi += math.Pow(expected-actual, 2)
	}

	return chi
}

func FindKey(b []byte) (byte, float64, []byte) {
	var pt []byte
	var key byte

	char := 0x00
	score := math.MaxFloat64
	for char != 0xff {
		curPt := crypto.XorSingle(b, byte(char))
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
