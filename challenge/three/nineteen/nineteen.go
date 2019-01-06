package nineteen

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/kdhageman/go-cryptopals/file"
	"github.com/logrusorgru/aurora"
	"math"
)

func findKeystreamByte(col []byte) byte {
	minChi, minC := math.MaxFloat64, 0
	for c := 0; c < 256; c++ {
		var s []byte
		for _, b := range col {
			s = append(s, b^byte(c))
		}
		chi := crypto.ChiSquared(string(s))
		if chi < minChi {
			minChi = chi
			minC = c
		}
	}
	return byte(minC)
}

type ch struct{}

func (c *ch) Solve() error {
	originals, err := file.ReadBase64Lines("challenge/three/nineteen/input.txt")
	if err != nil {
		return err
	}

	key := crypto.RandomKey(16)
	ctr, err := crypto.NewCtr(key, 0)
	if err != nil {
		return err
	}

	var ciphertexts [][]byte
	for _, original := range originals {
		ct, err := ctr.Encrypt(original)
		if err != nil {
			return err
		}
		ciphertexts = append(ciphertexts, ct)
	}

	consideredCts := map[int]bool{}
	for i := range ciphertexts {
		consideredCts[i] = true
	}

	var keystream []byte
	icol := 0
	for len(consideredCts) > 0 {
		var col []byte
		for i := range consideredCts {
			ct := ciphertexts[i]
			b := ct[icol]
			col = append(col, b)
			if icol >= len(ct)-1 {
				delete(consideredCts, i)
			}
		}
		keystream = append(keystream, findKeystreamByte(col))
		icol++
	}
	keystream[0] ^= 0x20
	fmt.Printf("Found keystream: %s\n", aurora.Cyan(fmt.Sprintf("%x", keystream)))

	fmt.Println("Plaintext")
	for _, ct := range ciphertexts {
		pt := crypto.Xor(ct, keystream)
		fmt.Printf("%s\n", aurora.Cyan(string(pt)))
	}
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
