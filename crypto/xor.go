package crypto

import (
	"github.com/pkg/errors"
	"math"
)

var (
	InvalidLengthErr = errors.New("arrays have different lengths")
)

func Xor(pt []byte, key []byte) ([]byte, error) {
	if len(pt) != len(key) {
		return nil, InvalidLengthErr
	}
	var ct []byte
	for i := range pt {
		ct = append(ct, pt[i]^key[i])
	}

	return ct, nil
}

func XorSingle(pt []byte, key byte) []byte {
	var res []byte
	for i := range pt {
		res = append(res, pt[i]^key)
	}
	return res
}

func XorRepeat(pt []byte, key []byte) []byte {
	var ct []byte
	i := 0
	for _, b := range pt {
		k := key[i%len(key)]
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
	blockc := int(math.Round(float64(len(b)) / float64(bs)))
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
			if len(c) == r {
				break
			}
			col = append(col, c[r])
		}
		res = append(res, col)
	}
	return res
}

func breakXorKeysize(ct []byte) (int, error) {
	numBlocks := len(ct) / 40

	maxDist := 0.0
	maxKs := -1

	for ks := 2; ks < 40; ks++ {
		var blocks [][]byte
		for i := 0; i < numBlocks; i++ {
			b := ct[i*ks : (i+1)*ks]
			blocks = append(blocks, b)
		}

		distSum := 0
		for i := 0; i < numBlocks-1; i++ {
			hd, err := HammingDistance(blocks[i], blocks[i+1])
			if err != nil {
				return 0, err
			}
			distSum += hd
		}

		dist := float64(distSum) / float64(ks)

		if dist > maxDist {
			maxDist = dist
			maxKs = ks
		}
	}

	return maxKs, nil
}

func BreakXor(ct []byte) (pt []byte, key []byte, err error) {
	ks, err := breakXorKeysize(ct)
	if err != nil {
		return nil, nil, err
	}

	blocks := InBlocks(ct, ks)
	blocks = Transpose(blocks)

	for _, block := range blocks {
		k, _, _ := FindKey(block)
		key = append(key, k)
	}

	pt = XorRepeat(ct, key)
	return pt, key, nil
}
