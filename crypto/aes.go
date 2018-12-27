package crypto

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"math"
	"math/rand"
)

var (
	NoBlockSizeFoundErr = errors.New("failed to find block size")
	NoByteFoundErr      = errors.New("failed to detect a plaintext byte")
)

type Oracle func([]byte) ([]byte, error)

type Mode int

func (m Mode) String() string {
	return map[int]string{
		0: "ECB",
		1: "CBC",
	}[int(m)]
}

const (
	ECB = Mode(0)
	CBC = Mode(1)
)

type CiphertextSizeErr struct {
	bsize int
	ksize int
}

func (err CiphertextSizeErr) Error() string {
	return fmt.Sprintf("keysize %d does not divide block size %d", err.ksize, err.bsize)
}

func EncryptEcb(pt []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pt = PadPkcs7(pt, len(key))

	var ct []byte
	blocks := InBlocks(pt, len(key))
	for _, block := range blocks {
		encrypted := make([]byte, len(block))
		c.Encrypt(encrypted, block)
		ct = append(ct, encrypted...)
	}

	return ct, nil
}

func DecryptEcb(ct []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%len(key) != 0 {
		return nil, CiphertextSizeErr{len(ct), len(key)}
	}
	var pt []byte
	blocks := InBlocks(ct, len(key))
	for _, block := range blocks {
		decrypted := make([]byte, len(block))
		c.Decrypt(decrypted, block)
		pt = append(pt, decrypted...)
	}

	return pt, nil
}

func EncryptCbc(pt []byte, key []byte, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pt = PadPkcs7(pt, len(key))

	var ct []byte
	blocks := InBlocks(pt, len(key))
	for _, block := range blocks {
		xored, err := Xor(block, iv)
		if err != nil {
			return nil, err
		}
		c.Encrypt(iv, xored)
		ct = append(ct, iv...)
	}

	return ct, nil
}

func DecryptCbc(ct []byte, key []byte, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%len(key) != 0 {
		return nil, CiphertextSizeErr{len(ct), len(key)}
	}
	var pt []byte
	blocks := InBlocks(ct, len(key))
	for _, block := range blocks {
		decrypted := make([]byte, len(block))
		c.Decrypt(decrypted, block)
		xored, err := Xor(decrypted, iv)
		if err != nil {
			return nil, err
		}
		pt = append(pt, xored...)
		iv = block
	}
	return pt, nil
}

func RandomKey(ksize int) []byte {
	var key []byte
	for i := 0; i < ksize; i++ {
		b := byte(rand.Intn(256))
		key = append(key, b)
	}
	return key
}

func DetectMode(oracle Oracle, bsize int) (Mode, error) {
	pt := repeatedByte(0xff, bsize*3)
	ct, err := oracle(pt)
	if err != nil {
		return 0, err
	}
	second := ct[bsize : 2*bsize]
	third := ct[2*bsize : 3*bsize]

	if bytes.Equal(second, third) {
		return ECB, nil
	}

	return CBC, nil
}

func DetectBlocksize(oracle Oracle) (int, error) {
	prefix := []byte{0x41}
	bsize := 0
	var prev []byte
	for i := 1; i < 40; i++ {
		ct, err := oracle(prefix)
		if err != nil {
			return 0, err
		}
		if prev != nil && bytes.Equal(prev[:i-1], ct[:i-1]) {
			bsize = i - 1
			break
		}
		prev = ct
		prefix = append(prefix, 0x41)
	}
	if bsize == 0 {
		return 0, NoBlockSizeFoundErr
	}
	return bsize, nil
}

func repeatedByte(b byte, l int) []byte {
	var res []byte
	for i := 0; i < l; i++ {
		res = append(res, b)
	}
	return res
}

func PaddingOracleAttack(oracle Oracle) ([]byte, error) {
	bsize, err := DetectBlocksize(oracle)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Found block size: %d\n", aurora.Cyan(bsize))
	mode, err := DetectMode(oracle, bsize)
	fmt.Printf("Found encryption mode: %s\n", aurora.Cyan(mode))

	pt := repeatedByte(0xff, bsize-1)

	block := 0
Outer:
	for {
		for i := bsize - 1; i >= 0; i-- {
			padding := repeatedByte(0xff, i)

			targetCt, err := oracle(padding)
			if err != nil {
				return nil, err
			}

			found := false
			for candidate := 0; candidate <= math.MaxUint8; candidate++ {
				candidatePt := append(pt[len(pt)-bsize+1:], byte(candidate)) // use last 'bsize-1' discovered plain text bytes + the candidate byte for creating the candidate plain text
				candidateCt, err := oracle(candidatePt)
				if err != nil {
					return nil, err
				}
				if bytes.Equal(candidateCt[:bsize], targetCt[block*bsize:(block+1)*bsize]) {
					pt = append(pt, byte(candidate))
					found = true
					break
				}
			}
			if !found {
				// the algorithm has not found a candidate, because of the PKCS7 padding (last two bytes are 0x02, whereas the padding was a 0x01 in the last iteration)
				break Outer
			}
		}
		block++
	}

	// first bsize-1 padding bits not returned
	// last byte is a 0x01 padding byte and therefore should not be returned
	return pt[bsize-1 : len(pt)-1], nil
}
