package seven

import (
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/crypto"
	"github.com/logrusorgru/aurora"
	"io/ioutil"
)

var (
	key = "YELLOW SUBMARINE"
)

type ch struct{}

func (c *ch) Solve() error {
	ct, err := ioutil.ReadFile("challenge/seven/input.txt")
	if err != nil {
		return err
	}
	base64.StdEncoding.Decode(ct, ct)

	k := []byte(key)

	pt, err := crypto.DecryptEcb(ct, k)
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted plain text:\n%s\n", aurora.Cyan(string(pt)))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
