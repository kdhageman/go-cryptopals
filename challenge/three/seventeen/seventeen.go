package seventeen

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
	"math"
	"math/rand"
	"os"
)

func readInput() ([][]byte, error) {
	f, err := os.Open("challenge/three/seventeen/input.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var res [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		b, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, nil
}

func randomPt(pts [][]byte) []byte {
	i := rand.Intn(len(pts))
	return pts[i]
}

type Encryptor func() ([]byte, error)
type Decryptor func(ct []byte) (validPadding bool, error error)

func oracle() (Encryptor, Decryptor, error) {
	pts, err := readInput()
	if err != nil {
		return nil, nil, err
	}
	key := crypto.RandomKey(16)
	iv := crypto.RandomKey(16)

	enc := func() ([]byte, error) {
		pt := randomPt(pts)
		return crypto.EncryptCbc(pt, key, iv)
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

	ct, err := enc()
	if err != nil {
		return err
	}

	// todo: all blocks
	// todo: all bytes in block

	var candidates []byte
	for i := 0; i <= math.MaxUint8; i++ {
		target := ct[len(ct)-aes.BlockSize:]
		tampered := bytes.Repeat([]byte{0xff}, 15)
		tampered = append(tampered, byte(i))
		tampered = append(tampered, target...)

		validPadding, err := dec(tampered)
		if err != nil {
			return err
		}
		if validPadding {
			candidates = append(candidates, byte(i))
		}
	}

	fmt.Printf("Possible candidates: %s\n", aurora.Cyan(fmt.Sprintf("%q", candidates)))
	pt = append(pt, candidates...)

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
