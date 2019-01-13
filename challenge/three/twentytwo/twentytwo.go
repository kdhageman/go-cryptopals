package twentytwo

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto/mersenne"
	"github.com/logrusorgru/aurora"
)

func untemper(n int32) uint32 {
	y := uint64(n) & 0xffffffff
	y ^= y >> 18
	y ^= (y << 15) & 0xefc60000
	y ^= (y << 7) & 0x9d2c5680
	y ^= y >> 11
	return uint32(y)
}

type ch struct{}

func (c *ch) Solve() error {
	seed := 5489
	mt := mersenne.New()
	mt.Seed(seed)

	expected := make([]int32, 624)
	state := make([]uint32, 624)
	for i := 0; i < 624; i++ {
		v, err := mt.Rand()
		if err != nil {
			return err
		}
		expected[i] = v
		state[i] = untemper(v)
	}

	other := mersenne.FromSlice(state)
	actual := make([]int32, 624)
	for i := 0; i < 624; i++ {
		v, err := other.Rand()
		if err != nil {
			return err
		}
		actual[i] = v
	}

	for i := range expected {
		if expected[i] != actual[i] {
			fmt.Printf("Expected %11d, but got %11d\n", aurora.Cyan(expected[i]), aurora.Cyan(actual[i]))
		}
	}

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
