package two

import (
	"github.com/kdhageman/gocrypto/challenge"
	"encoding/hex"
	cr "github.com/kdhageman/gocrypto/crypto"
	"bytes"
)

var (
	inputs = []string{
		"1c0111001f010100061a024b53535009181c",
		"686974207468652062756c6c277320657965",
	}
	expected =
		"746865206b696420646f6e277420706c6179"
)

type ch struct{}

func (c *ch) Solve() error {
	a, err := hex.DecodeString(inputs[0])
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(inputs[1])
	if err != nil {
		return err
	}

	res, err := cr.Xor(a,b)
	if err != nil {
		return err
	}

	e, err := hex.DecodeString(expected)
	if err != nil {
		return err
	}

	if !bytes.Equal(res, e)  {
		return challenge.WrongOutputErr(e, res)
	}

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
