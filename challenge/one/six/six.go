package six

import (
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/crypto"
	"github.com/logrusorgru/aurora"
	"io/ioutil"
)

type ch struct{}

func (c *ch) Solve() error {
	ct, err := ioutil.ReadFile("challenge/one/six/input.txt")
	if err != nil {
		return err
	}
	base64.StdEncoding.Decode(ct, ct)

	pt, key, err := crypto.BreakXor(ct)
	if err != nil {
		return err
	}

	fmt.Printf("Key: %v\n", aurora.Cyan(key))
	fmt.Printf("Decrypted plain text:\n%s\n", aurora.Cyan(string(pt)))
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
