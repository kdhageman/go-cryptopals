package fourteen

import (
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
	"io/ioutil"
	"math/rand"
)

type ch struct{}

func oracle() (crypto.Oracle, error) {
	key := crypto.RandomKey(16)
	prefix := crypto.RandomKey(rand.Intn(16))
	suffix, err := ioutil.ReadFile("challenge/two/twelve/suffix.txt")
	if err != nil {
		return nil, err
	}
	base64.StdEncoding.Decode(suffix, suffix)

	f := func(pt []byte) ([]byte, error) {
		pt = append(prefix, pt...)
		pt = append(pt, suffix...)
		ct, err := crypto.EncryptEcb(pt, key)
		if err != nil {
			return nil, err
		}
		return ct, nil
	}

	return f, nil
}

func (c *ch) Solve() error {
	f, err := oracle()
	if err != nil {
		return err
	}
	pt, err := crypto.RandomPaddingOracleAttack(f)
	if err != nil {
		return err
	}
	fmt.Printf("Found plain text:\n%q\n", aurora.Cyan(pt))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
