package crypto

import "github.com/pkg/errors"

var (
	InvalidLengthErr = errors.New("arrays have different lengths")
)

func Xor(a,b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, InvalidLengthErr
	}
	var res []byte
	for i := range a {
		res = append(res, a[i] ^ b[i])
	}

	return res, nil
}

func XorSingle(a []byte, b byte) []byte {
	var res []byte
	for i := range a {
		res = append(res, a[i] ^ b)
	}
	return res
}