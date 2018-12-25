package crypto

import (
	"testing"
		"reflect"
)

func TestHammingDistance(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")

	hd, err := HammingDistance(a, b)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if hd != 37 {
		t.Fatalf("Actual hamming distance %d does not match expected %d", hd, 37)
	}
}

func TestInBlocks(t *testing.T) {
	tests := []struct {
		name string
		bs int
		expectedSize int
	}{
		{
			name: "Block size of one",
			bs: 1,
			expectedSize: 8,
		},
		{
			name: "" +
				"Dividing block size",
			bs: 2,
			expectedSize: 4,
		},
		{
			name: "Non-dividing block size",
			bs: 3,
			expectedSize: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := []byte("12345678")

			blocks := InBlocks(b, test.bs)
			if len(blocks) != test.expectedSize {
				t.Fatalf("Expected %d blocks, but got %d", test.expectedSize, len(blocks))
			}
		})
	}

}

func TestTranspose(t *testing.T) {
	tests := []struct {
		name string
		input [][]byte
		expected [][]byte
	}{
		{
			name: "Normal",
			input: [][]byte{
				{0, 1, 2, 3},
				{4, 5,6 ,7},
			},
			expected: [][]byte{
				{0, 4},
				{1, 5},
				{2, 6},
				{3, 7},
			},
		},
		{
			name: "Unequal block sizes",
			input: [][]byte{
				{0, 1, 2},
				{3, 4},
			},
			expected: [][]byte{
				{0, 3},
				{1, 4},
				{2},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := Transpose(test.input)
			if !reflect.DeepEqual(actual, test.expected) {
				t.Fatalf("Expected %v, but got %v", test.expected, actual)
			}
		})
	}
}