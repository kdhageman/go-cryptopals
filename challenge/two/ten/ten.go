package ten

import (
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
	"io/ioutil"
)

var (
	key = "YELLOW SUBMARINE"
)

type ch struct{}

func (c *ch) Solve() error {
	ct, err := ioutil.ReadFile("challenge/two/ten/input.txt")
	if err != nil {
		return err
	}
	base64.StdEncoding.Decode(ct, ct)

	var iv []byte
	for i := 0; i < 16; i++ {
		iv = append(iv, 0x00)
	}

	k := []byte(key)

	pt, err := crypto.DecryptCbc(ct, k, iv)
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted plain text:\n%s\n", aurora.Cyan(string(pt)))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
