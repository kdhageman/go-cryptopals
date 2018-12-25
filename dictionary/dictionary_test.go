package dictionary

import (
	"testing"
		)

func TestScore(t *testing.T) {
	input := "abc"
	expected := 8.167 + 1.492 + 2.782
	actual := Score(input)
	if actual != expected {
		t.Fatalf("Expected %f, but got %f", expected, actual)
	}
}
