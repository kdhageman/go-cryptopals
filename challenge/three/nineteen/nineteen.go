package nineteen

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/kdhageman/go-cryptopals/file"
	"github.com/logrusorgru/aurora"
	"math"
)

func FindKeystreamByte(col []byte, sos bool) byte {
	minChi, minC := math.MaxFloat64, 0
	for c := 0; c < 256; c++ {
		var s []byte
		for _, b := range col {
			s = append(s, b^byte(c))
		}
		chi := crypto.ChiSquared(string(s), sos)
		if chi < minChi {
			minChi = chi
			minC = c
		}
	}
	return byte(minC)
}

func EncryptBase64File(filename string, ctr crypto.Ctr) ([][]byte, error) {
	originals, err := file.ReadBase64Lines(filename)
	if err != nil {
		return nil, err
	}

	var cts [][]byte
	for _, original := range originals {
		ct, err := ctr.Encrypt(original)
		if err != nil {
			return nil, err
		}
		cts = append(cts, ct)
	}
	return cts, nil
}

type ch struct{}

func (c *ch) Solve() error {
	key := crypto.RandomKey(16)
	ctr, err := crypto.NewCtr(key, 0)
	if err != nil {
		return err
	}

	cts, err := EncryptBase64File("challenge/three/nineteen/input.txt", ctr)
	if err != nil {
		return err
	}

	consideredCts := map[int]bool{}
	for i := range cts {
		consideredCts[i] = true
	}

	var keystream []byte
	icol := 0
	for len(consideredCts) > 0 {
		var col []byte
		for i := range consideredCts {
			ct := cts[i]
			b := ct[icol]
			col = append(col, b)
			if icol >= len(ct)-1 {
				delete(consideredCts, i)
			}
		}
		sos := false
		if icol == 0 {
			sos = true
		}
		keystream = append(keystream, FindKeystreamByte(col, sos))
		icol++
	}
	keystream[0] ^= 0x20
	fmt.Printf("Found keystream: %s\n", aurora.Cyan(fmt.Sprintf("%x", keystream)))

	fmt.Println("Plaintext")
	for _, ct := range cts {
		pt := crypto.Xor(ct, keystream)
		fmt.Printf("%s\n", aurora.Cyan(string(pt)))
	}
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
