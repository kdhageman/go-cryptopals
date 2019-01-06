package eighteen

import (
	"encoding/base64"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
)

var (
	input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
)

type ch struct{}

func (c *ch) Solve() error {
	ct, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}

	ctr, err := crypto.NewCtr([]byte("YELLOW SUBMARINE"), 0)
	pt, err := ctr.Decrypt(ct)
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted plaintext: %s\n", aurora.Cyan(string(pt)))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
