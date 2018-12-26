package nine

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/crypto"
	"github.com/logrusorgru/aurora"
)

var (
	input = "YELLOW SUBMARINE"
)

type ch struct{}

func (c *ch) Solve() error {
	unpadded := []byte(input)
	padded, err := crypto.PadPkcs7(unpadded, 20)
	if err != nil {
		return err
	}

	fmt.Printf("First sixteen bytes: %s\n", aurora.Cyan(string(padded[:16])))
	fmt.Printf("Last four bytes: %q\n", aurora.Cyan(padded[16:]))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
