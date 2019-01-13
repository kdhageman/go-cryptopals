package twentytwo

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto/mersenne"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"math/rand"
	"time"
)

type ch struct{}

func rng() (int32, error) {
	mt := mersenne.New()
	seed := time.Now().Unix() + 40 + rand.Int63n(60000)
	fmt.Printf("Actual seed: %d\n", aurora.Cyan(seed))
	mt.Seed(int(seed))
	return mt.Rand()
}

func (c *ch) Solve() error {
	target, err := rng()
	if err != nil {
		return err
	}

	found := false
	mt := mersenne.New()
	lower := time.Now().Unix() + 35
	for i := 0; i < 80000; i++ {
		seed := lower + int64(i)
		mt.Seed(int(seed))
		actual, err := mt.Rand()
		if err != nil {
			return err
		}
		if actual == target {
			fmt.Printf("Found seed: %d\n", aurora.Cyan(seed))
			found = true
			break
		}
	}

	if !found {
		return errors.New("failed to find seed")
	}

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
