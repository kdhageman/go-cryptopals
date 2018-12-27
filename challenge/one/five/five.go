package five

import (
	"bytes"
	"encoding/hex"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
)

var (
	input    = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	key      = "ICE"
)

type ch struct{}

func (c *ch) Solve() error {
	k := []byte(key)

	i := []byte(input)
	e, err := hex.DecodeString(expected)
	if err != nil {
		return err
	}
	actual := crypto.XorRepeat(i, k)

	if !bytes.Equal(e, actual) {
		return challenge.WrongOutputErr(expected, actual)
	}

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
