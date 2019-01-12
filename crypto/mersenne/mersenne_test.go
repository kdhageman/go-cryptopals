package mersenne

import (
	"testing"
)

func TestSeed(t *testing.T) {
	params := DefaultParams

	mt := mersenneTwister{
		params: DefaultParams,
		state:  make([]int, params.n),
	}
	if err := mt.Seed(0); err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	for i := 1; i < params.n; i++ {
		if mt.state[i] == 0 {
			t.Fatalf("Unexpected state to be non-zero")
		}
	}
}

func TestNew(t *testing.T) {
	params := Params{
		r: 3,
		w: 5,
	}
	New(params)
}
