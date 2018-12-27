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

func EncryptionOracle(pt []byte, ksize int) ([]byte, Mode, error) {
	prefix, suffix := RandomKey(5+rand.Intn(6)), RandomKey(5+rand.Intn(6))
	pt = append(prefix, pt...)
	pt = append(pt, suffix...)
	pt = PadPkcs7(pt, ksize)

	key := RandomKey(ksize)
	mode := Mode(rand.Intn(2))
	var encrypted []byte
	var err error
	switch mode {
	case ECB:
		encrypted, err = EncryptEcb(pt, key)
		break
	case CBC:
		iv := RandomKey(ksize)
		encrypted, err = EncryptCbc(pt, key, iv)
		break
	}
	if err != nil {
		return nil, mode, err
	}
	return encrypted, mode, nil
}

func DetectMode(ct []byte, bsize int) Mode {
	dist := map[string]bool{}
	blocks := InBlocks(ct, bsize)

	for _, b := range blocks {
		dist[string(b)] = true
	}
	if len(blocks)-len(dist) > 0 {
		return ECB
	}
	return CBC
}

func DetectBlocksize(oracle func(prefix []byte) (ct []byte, err error)) (int, error) {
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

func prefix(l int) []byte {
	var res []byte
	for i := 0; i < l; i++ {
		res = append(res, 0x41)
	}
	return res
}

func PaddingOracleAttack(oracle func(prefix []byte) (ct []byte, err error)) ([]byte, error) {
	bsize, err := DetectBlocksize(oracle)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Found block size: %d\n", aurora.Cyan(bsize))
	ct, err := oracle([]byte{})
	if err != nil {
		return nil, err
	}
	mode := DetectMode(ct, bsize)
	fmt.Printf("Found encryption mode: %s\n", aurora.Cyan(mode))

	var pt []byte

	for j := bsize - 1; j >= 0; j-- {
		p := append(prefix(j))
		prefixCt, err := oracle(p)
		p = append(p, pt...) // todo: replace by something else!
		if err != nil {
			return nil, err
		}

		foundByte := false
		for i := 0; i <= math.MaxUint8; i++ {
			curPrefix := append(p, byte(i))
			curCt, err := oracle(curPrefix)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(curCt[:bsize], prefixCt[:bsize]) {
				pt = append(pt, byte(i))
				foundByte = true
				break
			}
		}
		if !foundByte {
			return nil, NoByteFoundErr
		}
	}

	return pt, nil
}
