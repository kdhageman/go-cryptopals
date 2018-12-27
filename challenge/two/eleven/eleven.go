package eleven

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
	"math/rand"
)

type ch struct{}

func oracle(ksize int) (crypto.Oracle, crypto.Mode) {
	mode := crypto.Mode(rand.Intn(2))

	return func(pt []byte) ([]byte, error) {
		prefix := crypto.RandomKey(5 + rand.Intn(6))
		suffix := crypto.RandomKey(5 + rand.Intn(6))
		pt = append(prefix, pt...)
		pt = append(pt, suffix...)
		pt = crypto.PadPkcs7(pt, ksize)

		key := crypto.RandomKey(ksize)
		var encrypted []byte
		var err error
		switch mode {
		case crypto.ECB:
			encrypted, err = crypto.EncryptEcb(pt, key)
			break
		case crypto.CBC:
			iv := crypto.RandomKey(ksize)
			encrypted, err = crypto.EncryptCbc(pt, key, iv)
			break
		}
		if err != nil {
			return nil, err
		}
		return encrypted, nil
	}, mode
}

func (c *ch) Solve() error {
	counter := struct {
		correct float64
		total   float64
	}{}

	for i := 0; i < 100; i++ {
		o, actual := oracle(16)

		detected, err := crypto.DetectMode(o, 16)
		if err != nil {
			return err
		}
		if actual == detected {
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
