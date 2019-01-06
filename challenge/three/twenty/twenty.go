package twenty

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/challenge/three/nineteen"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
)

type ch struct{}

func (c *ch) Solve() error {
	key := crypto.RandomKey(16)
	ctr, err := crypto.NewCtr(key, 0)
	if err != nil {
		return err
	}
	cts, err := nineteen.EncryptBase64File("challenge/three/twenty/input.txt", ctr)
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
		keystream = append(keystream, nineteen.FindKeystreamByte(col, sos))
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
