package crypto

import (
	"github.com/pkg/errors"
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
