package crypto_test

import (
	"github.com/kdhageman/gocrypto/crypto"
	"math"
	"testing"
)

func TestEnDict(t *testing.T) {
	s := 0.0
	for _, v := range crypto.EnDict {
		s += v
	}
	expected := 1.0 - crypto.NonAlphabetic
	if s != expected {
		t.Fatalf("Dictionary weights MUST sum to %f, but are %f", expected, s)
	}
}

func TestScore(t *testing.T) {
	input := "abc"

	expected := math.Pow(3*crypto.EnDict['a']-1, 2) +
		math.Pow(3*crypto.EnDict['b']-1, 2) +
		math.Pow(3*crypto.EnDict['c']-1, 2)

	actual := crypto.ChiSquared(input)
	if actual != expected {
		t.Fatalf("Expected %f, but got %f", expected, actual)
	}
}
