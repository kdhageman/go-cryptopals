package crypto

import (
	"crypto/aes"
	"fmt"
	"math/rand"
)

type Mode int

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

func EncryptRandomly(pt []byte, ksize int) ([]byte, Mode, error) {
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
