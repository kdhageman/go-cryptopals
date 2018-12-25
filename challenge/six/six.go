package six

import (
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/crypto"
	"io/ioutil"
)

type ch struct{}

func (c *ch) Solve() error {
	ct, err := ioutil.ReadFile("challenge/six/input.txt")
	if err != nil {
		return err
	}
	base64.StdEncoding.Decode(ct, ct)

	pt, _, err := crypto.BreakXor(ct)
	if err != nil {
		return err
	}

	fmt.Println(string(pt))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
