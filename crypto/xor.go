package crypto

import (
	"github.com/pkg/errors"
	"math"
)

var (
	InvalidLengthErr = errors.New("arrays have different lengths")
)

func Xor(a, b []byte) []byte {
	l := len(a)
	if len(b) < len(a) {
		l = len(b)
	}
	var res []byte
	for i := 0; i < l; i++ {
		res = append(res, a[i]^b[i])
	}

	return res
}

func XorSingle(a []byte, s byte) []byte {
	var res []byte
	for i := range a {
		res = append(res, a[i]^s)
	}
	return res
}

func XorRepeat(a, r []byte) []byte {
	var ct []byte
	i := 0
	for _, b := range a {
		k := r[i%len(r)]
		ct = append(ct, b^k)
		i++
	}
	return ct
}

func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, InvalidLengthErr
	}

	hd := 0
	for i := range a {
		xor := int(a[i] ^ b[i])
		for j := 0; j < 8; j++ {
			hd += (xor >> uint(j)) & 1
		}
	}

	return hd, nil
}

func InBlocks(b []byte, bs int) [][]byte {
	var res [][]byte

	blockc := len(b) / bs
	if len(b)%bs != 0 {
		blockc++
	}
	for i := 0; i < blockc; i++ {
		start := i * bs
		end := (i + 1) * bs
		if end > len(b) {
			end = len(b)
		}
		res = append(res, b[start:end])
	}
	return res
}

func Transpose(b [][]byte) [][]byte {
	var res [][]byte
	for r := 0; r < len(b[0]); r++ {
		var col []byte
		for _, c := range b {
			if len(c) <= r {
				break
			}
			col = append(col, c[r])
		}
		res = append(res, col)
	}
	return res
}

func ProbableXorKeysize(ct []byte) (int, error) {
	numBlocks := len(ct) / 40

	dist := math.MaxFloat64
	keysize := -1

	for curKeysize := 2; curKeysize < 40; curKeysize++ {
		var blocks [][]byte
		for i := 0; i < numBlocks; i++ {
			b := ct[i*curKeysize : (i+1)*curKeysize]
			blocks = append(blocks, b)
		}

		sum := 0
		for i := 0; i < numBlocks-1; i++ {
			hd, err := HammingDistance(blocks[i], blocks[i+1])
			if err != nil {
				return 0, err
			}
			sum += hd
		}

		curDist := float64(sum) / float64(curKeysize)

		if curDist < dist {
			dist = curDist
			keysize = curKeysize
		}
	}

	return keysize, nil
}

func BreakXor(ct []byte) (pt []byte, key []byte, err error) {
	keysize, err := ProbableXorKeysize(ct)
	if err != nil {
		return nil, nil, err
	}

	blocks := InBlocks(ct, keysize)
	blocks = Transpose(blocks)

	for _, block := range blocks {
		k, _, _ := FindKey(block)
		key = append(key, k)
	}

	pt = XorRepeat(ct, key)
	return pt, key, nil
}
