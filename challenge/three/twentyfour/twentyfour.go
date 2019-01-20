package twentyfour

import (
	"github.com/kdhageman/go-cryptopals/challenge"
)

type ch struct{}

func (c *ch) Solve() error {
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
