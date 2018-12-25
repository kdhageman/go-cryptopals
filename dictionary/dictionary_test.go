package dictionary_test

import (
	"github.com/kdhageman/gocrypto/dictionary"
	"math"
	"testing"
)

func TestEnDict(t *testing.T) {
	s := 0.0
	for _, v := range dictionary.EnDict {
		s += v
	}
	if s != 1.0 {
		t.Fatalf("Dictionary weights MUST equal %f, but are %f", 1.0, s)
	}
}

func TestScore(t *testing.T) {
	input := "abc"

	expected := math.Pow(3*dictionary.EnDict['a']-1, 2) +
		math.Pow(3*dictionary.EnDict['b']-1, 2) +
		math.Pow(3*dictionary.EnDict['c']-1, 2)

	actual := dictionary.ChiSquared(input)
	if actual != expected {
		t.Fatalf("Expected %f, but got %f", expected, actual)
	}
}
