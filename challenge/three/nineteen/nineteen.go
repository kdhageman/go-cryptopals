package nineteen

import (
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/kdhageman/go-cryptopals/file"
)

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

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
