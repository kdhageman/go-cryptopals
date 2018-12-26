package eleven

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/crypto"
	"github.com/logrusorgru/aurora"
	"io/ioutil"
)

type ch struct{}

func (c *ch) Solve() error {
	pt, err := ioutil.ReadFile("challenge/two/eleven/tux.jpg")
	if err != nil {
		return err
	}

	counter := struct {
		correct float64
		total   float64
	}{}

	for i := 0; i < 100; i++ {
		ct, mode, err := crypto.EncryptionOracle([]byte(pt), 16)
		if err != nil {
			return err
		}

		detected := crypto.DetectMode(ct, 16)
		if mode == detected {
			counter.correct++
		}
		counter.total++
	}

	fmt.Printf("Accuracy: %.1f%%\n", aurora.Cyan(counter.correct/counter.total*100.0))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
