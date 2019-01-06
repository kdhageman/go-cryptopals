package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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

	pt = PadPkcs7(pt, aes.BlockSize)

	var ct []byte
	blocks := InBlocks(pt, aes.BlockSize)
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

func EncryptCbc(pt []byte, key []byte, initialIv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pt = PadPkcs7(pt, aes.BlockSize)

	iv := make([]byte, len(initialIv))
	copy(iv, initialIv)
	var ct []byte
	blocks := InBlocks(pt, aes.BlockSize)
	for _, block := range blocks {
		xored := Xor(block, iv)
		c.Encrypt(iv, xored)
		ct = append(ct, iv...)
	}

	return ct, nil
}

func DecryptCbc(ct []byte, key []byte, initialIv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, CiphertextSizeErr{len(ct), aes.BlockSize}
	}

	iv := make([]byte, len(initialIv))
	copy(iv, initialIv)
	var pt []byte
	blocks := InBlocks(ct, aes.BlockSize)
	for _, block := range blocks {
		decrypted := make([]byte, aes.BlockSize)
		c.Decrypt(decrypted, block)
		xored := Xor(decrypted, iv)
		pt = append(pt, xored...)
		iv = block
	}
	return RemovePkcs7(pt, 16)
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
	pt := bytes.Repeat([]byte{0xff}, bsize*3)
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
	var prev, prefix []byte
	for i := 1; i < 256; i++ {
		prefix = append(prefix, 0xff)
		ct, err := oracle(prefix)
		if err != nil {
			return 0, err
		}
		if prev != nil && len(prev) != len(ct) {
			return len(ct) - len(prev), nil
		}
		prev = ct
	}
	return 0, NoBlockSizeFoundErr
}

// Under the assumption that the prefix is smaller than the block size
func DetectPrefixSize(oracle Oracle, bsize int) (int, error) {
	var padding []byte
	var prev []byte
	for i := 0; i < bsize; i++ {
		ct, err := oracle(padding)
		if err != nil {
			return 0, err
		}
		if prev != nil && bytes.Equal(prev[:bsize], ct[:bsize]) {
			return bsize - i + 1, nil
		}
		prev = ct
		padding = append(padding, 0xff)
	}
	return 0, nil
}

func EbcPaddingOracleAttack(oracle Oracle) ([]byte, error) {
	bsize, err := DetectBlocksize(oracle)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Found block size: %d\n", aurora.Cyan(bsize))
	psize, err := DetectPrefixSize(oracle, bsize)
	fmt.Printf("Found prefix size: %d\n", aurora.Cyan(psize))
	mode, err := DetectMode(oracle, bsize)
	fmt.Printf("Found encryption mode: %s\n", aurora.Cyan(mode))

	pt := bytes.Repeat([]byte{0xff}, bsize-1)

	block := 0
Outer:
	for {
		for i := bsize - 1; i >= 0; i-- {
			padding := bytes.Repeat([]byte{0xff}, bsize-psize+i)

			targetCt, err := oracle(padding)
			if err != nil {
				return nil, err
			}
			targetCt = targetCt[(block+1)*bsize : (block+2)*bsize]

			found := false
			for candidate := 0; candidate <= math.MaxUint8; candidate++ {
				candidatePt := bytes.Repeat([]byte{0xff}, bsize-psize)
				candidatePt = append(candidatePt, pt[len(pt)-bsize+1:]...) // use last 'bsize-1' discovered plain text bytes + the candidate byte for creating the candidate plain text
				candidatePt = append(candidatePt, byte(candidate))
				candidateCt, err := oracle(candidatePt)
				if err != nil {
					return nil, err
				}
				candidateCt = candidateCt[bsize : 2*bsize]

				if bytes.Equal(candidateCt, targetCt) {
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

func IntToBytes(i uint64) []byte {
	var res []byte
	for i > 0 {
		res = append([]byte{byte(i % 256)}, res...)
		i = i >> 8
	}
	return res
}

func Reverse(inp []byte) []byte {
	res := make([]byte, len(inp))
	for i, b := range inp {
		res[len(inp)-i-1] = b
	}
	return res
}

type Ctr interface {
	Encrypt(pt []byte) ([]byte, error)
	Decrypt(ct []byte) ([]byte, error)
}

type ctr struct {
	nonce   []byte
	counter int64
	cipher  cipher.Block
}

func (c *ctr) Encrypt(pt []byte) ([]byte, error) {
	var ct []byte

	for _, block := range InBlocks(pt, aes.BlockSize) {
		counter := make([]byte, 8)
		binary.LittleEndian.PutUint64(counter, uint64(c.counter))
		c.counter++

		input := append(c.nonce, counter...)

		encrypted := make([]byte, aes.BlockSize)
		c.cipher.Encrypt(encrypted, input)

		xored := Xor(block, encrypted)

		ct = append(ct, xored...)
	}
	return ct, nil
}

func (c *ctr) Decrypt(ct []byte) ([]byte, error) {
	return nil, nil
}

func NewCtr(key []byte, nonce uint64) (Ctr, error) {
	if key == nil {
		key = RandomKey(aes.BlockSize)
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c := ctr{
		nonce:   make([]byte, 8),
		counter: 0,
		cipher:  cipher,
	}
	binary.LittleEndian.PutUint64(c.nonce, nonce)
	return &c, nil
}
