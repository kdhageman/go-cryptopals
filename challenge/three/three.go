package three

import (
	"encoding/hex"
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/dictionary"
)

var (
	input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)

type ch struct{}

func (ch) Solve() error {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		return err
	}

	_, _, pt := dictionary.FindKey(decoded)

	fmt.Printf("Resulting string: %s", string(pt))
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
