package four

import (
	"github.com/kdhageman/gocrypto/challenge"
		"bufio"
	"os"
	"fmt"
	"encoding/hex"
	"github.com/kdhageman/gocrypto/dictionary"
)

type ch struct {}

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
		_, score, pt := dictionary.FindKey(ct)
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