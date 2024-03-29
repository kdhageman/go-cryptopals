package crypto

import (
	"bytes"
	"reflect"
	"testing"
)

func TestXor(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected []byte
	}{
		{
			name:     "Blocks of equal length",
			a:        []byte{0x10, 0x10, 0x10},
			b:        []byte{0x01, 0x01, 0x01},
			expected: []byte{0x11, 0x11, 0x11},
		},
		{
			name:     "Blocks of unequal length",
			a:        []byte{0x1, 0x2},
			b:        []byte{0x4, 0x2, 0x1},
			expected: []byte{0x5, 0x0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Xor(tt.a, tt.b)
			if !bytes.Equal(tt.expected, actual) {
				t.Fatalf("Expected bytes %x, but got %x", tt.expected, actual)
			}
		})
	}
}

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
		name         string
		bs           int
		expectedSize int
	}{
		{
			name:         "Block size of one",
			bs:           1,
			expectedSize: 8,
		},
		{
			name: "" +
				"Dividing block size",
			bs:           2,
			expectedSize: 4,
		},
		{
			name:         "Non-dividing block size",
			bs:           3,
			expectedSize: 3,
		},
		{
			name:         "Block size large than input",
			bs:           20,
			expectedSize: 1,
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
		name     string
		input    [][]byte
		expected [][]byte
	}{
		{
			name: "Normal",
			input: [][]byte{
				{0, 1, 2, 3},
				{4, 5, 6, 7},
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
				{0, 1, 2, 3, 4},
				{10, 11, 12, 13, 14},
				{20, 21, 22},
			},
			expected: [][]byte{
				{0, 10, 20},
				{1, 11, 21},
				{2, 12, 22},
				{3, 13},
				{4, 14},
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
