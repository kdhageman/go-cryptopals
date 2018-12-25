package dictionary

import (
	"strings"
	"github.com/kdhageman/gocrypto/crypto"
)

var (
	frequencies = []float64{8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074, 1, 1, 1}
	scores = map[int32]float64{}
)

func init() {
	for i, r := range `abcdefghijklmnopqrstuvwxyz '"` {
		scores[r] = frequencies[i]
	}
}

func Score(s string) float64 {
	res := 0.0
	s = strings.ToLower(s)
	for _, r := range s {
		score, ok := scores[r]
		if !ok {
			score = -5
		}
		res += score
	}
	return res
}

func FindKey(b []byte) (key byte, score float64, pt []byte) {
	var resPt []byte

	char := 0x00
	maxScore := 0.0
	for char != 0xff {
		pt := crypto.XorSingle(b, byte(char))
		s := string(pt)
		score := Score(s)
		if score > maxScore {
			maxScore = score
			key = byte(char)
			resPt = pt
		}
		char += 0x01
	}

	return key, maxScore, resPt
}