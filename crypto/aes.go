package crypto

import (
	"crypto/aes"
	"fmt"
)

type CiphertextSizeErr struct {
	bsize int
	ksize int
}

func (err CiphertextSizeErr) Error() string {
	return fmt.Sprintf("keysize %d does not divide block size %d", err.ksize, err.bsize)
}

func DecryptEcb(b []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(b)%len(key) != 0 {
		return nil, CiphertextSizeErr{len(b), len(key)}
	}
	var pt []byte
	blocks := InBlocks(b, len(key))
	for _, block := range blocks {
		decrypted := make([]byte, len(block))
		c.Decrypt(decrypted, block)
		pt = append(pt, decrypted...)
	}

	return pt, nil
}
