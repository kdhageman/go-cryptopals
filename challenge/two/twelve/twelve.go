package twelve

import (
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/crypto"
	"github.com/logrusorgru/aurora"
	"io/ioutil"
)

type ch struct{}

func encryptionFunction() (func([]byte) ([]byte, error), error) {
	key := crypto.RandomKey(16)
	suffix, err := ioutil.ReadFile("challenge/two/twelve/suffix.txt")
	if err != nil {
		return nil, err
	}
	base64.StdEncoding.Decode(suffix, suffix)

	f := func(prefix []byte) ([]byte, error) {
		pt := append(prefix, suffix...)
		ct, err := crypto.EncryptEcb(pt, key)
		if err != nil {
			return nil, err
		}
		return ct, nil
	}

	return f, nil
}

func (c *ch) Solve() error {
	f, err := encryptionFunction()
	if err != nil {
		return err
	}
	pt, err := crypto.PaddingOracleAttack(f)

	fmt.Printf("Found plain text:\n%s\n", aurora.Cyan(pt))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
