package seventeen

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/kdhageman/go-cryptopals/file"
	"math/rand"
	"time"
)

var (
	NoCandidateErr = errors.New("found no candidates for plain text byte")
)

func init() {
	rand.Seed(time.Now().Unix())
}

func randomPt(pts [][]byte) []byte {
	i := rand.Intn(len(pts))
	return pts[i]
}

type Encrypt func() (ct []byte, iv []byte, err error)

type Decrypt func(ct []byte) (validPadding bool, error error)

func (d Decrypt) DecryptByteInBlock(target []byte, i int, prev []byte, pt []byte) (byte, error) {
	p := byte(16 - i)
	for j := 0; j < 256; j++ {
		crafted := make([]byte, 16)
		for k := 0; k < 16; k++ {
			crafted[k] = prev[k] ^ pt[k] ^ p
		}
		crafted[i] = byte(j)

		payload := append(crafted, target...)
		valid, err := d(payload)
		if err != nil {
			return 0x00, err
		}
		if valid {
			return byte(j) ^ p ^ prev[i], nil
		}
	}

	return 0x00, NoCandidateErr
}

func (d Decrypt) DecryptBlock(ct []byte, prev []byte) ([]byte, error) {
	pt := bytes.Repeat([]byte{0xff}, 16)
	for i := 15; i >= 0; i-- {
		p, err := d.DecryptByteInBlock(ct, i, prev, pt)
		if err != nil {
			return nil, err
		}
		pt[i] = p
	}
	return pt, nil
}

func oracle() (Encrypt, Decrypt, error) {
	pts, err := file.ReadBase64Lines("challenge/three/seventeen/input.txt")
	if err != nil {
		return nil, nil, err
	}
	key := crypto.RandomKey(aes.BlockSize)
	iv := crypto.RandomKey(aes.BlockSize)

	enc := func() ([]byte, []byte, error) {
		pt := randomPt(pts)
		ct, err := crypto.EncryptCbc(pt, key, iv)
		return ct, iv, err
	}
	dec := func(ct []byte) (bool, error) {
		_, err := crypto.DecryptCbc(ct, key, iv)
		if err != nil {
			if err == crypto.InvalidPaddingErr || err == crypto.BlocksizeErr {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
	return enc, dec, nil
}

type ch struct{}

func (c *ch) Solve() error {
	enc, dec, err := oracle()
	var pt []byte

	ct, iv, err := enc()
	if err != nil {
		return err
	}

	ct = append(iv, ct...)
	blocks := crypto.InBlocks(ct, 16)
	for i := 0; i < len(blocks)-1; i++ {
		prev, target := blocks[i], blocks[i+1]
		decrypted, err := dec.DecryptBlock(target, prev)
		if err != nil {
			return err
		}
		pt = append(pt, decrypted...)
	}
	fmt.Println(string(pt))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
