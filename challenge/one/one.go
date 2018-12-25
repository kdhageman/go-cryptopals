package one

import (
	"encoding/hex"
	"encoding/base64"
	"bytes"
	"github.com/kdhageman/gocrypto/challenge"
)

var (
	input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
)

type ch struct {}

func (c *ch) Solve() error {
	h, err := hex.DecodeString(input)
	if err != nil {
		return err
	}
	b, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return err
	}

	if !bytes.Equal(h, b) {
		return challenge.WrongOutputErr(b, h)
	}

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}