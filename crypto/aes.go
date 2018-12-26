package crypto

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand"
)

var (
	GlobalKey []byte
	Suffix    []byte
	BlockSize = 16
)

func init() {
	s := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	Suffix = make([]byte, len(s))
	base64.StdEncoding.Decode(Suffix, s)
}

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

func EncryptionOracleConsistent(prefix []byte) ([]byte, error) {
	if GlobalKey == nil {
		GlobalKey = RandomKey(BlockSize)
	}
	pt := append(prefix, Suffix...)
	ct, err := EncryptEcb(pt, GlobalKey)
	if err != nil {
		return nil, err
	}
	return ct, nil
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
