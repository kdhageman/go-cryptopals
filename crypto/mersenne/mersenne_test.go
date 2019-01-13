package mersenne

import (
	"testing"
)

func TestSeed(t *testing.T) {
	mt := mersenneTwister{
		state: make([]int, n),
	}
	mt.Seed(0)

	for i := 1; i < n; i++ {
		if mt.state[i] == 0 {
			t.Fatalf("Unexpected state to be non-zero")
		}
	}
}

func TestRand(t *testing.T) {
	expected := []int{
		-795755684,
		581869302,
		-404620562,
		-708632711,
		545404204,
		-133711905,
		-372047867,
		949333985,
		-1579004998,
		1323567403,
	}

	mt := New()
	if _, err := mt.Rand(); err == nil {
		t.Fatalf("Expected an error, but got none")
	}

	mt.Seed(5489)

	for i := range expected {
		actual, _ := mt.Rand()
		if expected[i] != actual {
			t.Fatalf("Expected %d, but got %d", expected[i], actual)
		}
	}
}
