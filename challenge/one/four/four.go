package four

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"os"
)

type ch struct{}

func (c *ch) Solve() error {
	f, err := os.Open("challenge/four/input.txt")
	if err != nil {
		return err
	}

	var maxScore float64
	var resPt string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		ct, err := hex.DecodeString(line)
		if err != nil {
			return err
		}
		_, score, pt := crypto.FindKey(ct)
		if score > maxScore {
			maxScore = score
			resPt = string(pt)
		}
	}
	fmt.Printf("Plaintext: %s", resPt)

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
