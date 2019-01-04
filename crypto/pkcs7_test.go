package crypto

import (
	"bytes"
	"testing"
)

func TestPadPkcs7(t *testing.T) {
	tests := []struct {
		name     string
		b        []byte
		bsize    int
		expected []byte
	}{
		{
			name:     "No padding required",
			b:        []byte("aaaaaa"),
			bsize:    3,
			expected: []byte("aaaaaa"),
		},
		{
			name:     "Single block padding",
			b:        []byte("aa"),
			bsize:    4,
			expected: append([]byte("aa"), 0x02, 0x02),
		},
		{
			name:     "Multiple blocks padding",
			b:        []byte("aaa"),
			bsize:    2,
			expected: append([]byte("aaa"), 0x01),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := PadPkcs7(tt.b, tt.bsize)
			if !bytes.Equal(tt.expected, actual) {
				t.Fatalf("Expected padded bytes %q, but got %q", tt.expected, actual)
			}
		})
	}
}

func TestRemovePkcs7(t *testing.T) {
	tests := []struct {
		name        string
		b           []byte
		expected    []byte
		expectedErr error
	}{
		{
			name:     "Valid",
			b:        []byte{0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06},
			expected: []byte{0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94},
		},
		{
			name:        "Invalid block size",
			b:           []byte{0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06},
			expectedErr: BlocksizeErr,
		},
		{
			name:        "Invalid padding",
			b:           []byte{0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x94, 0x06, 0x06, 0x06, 0x06, 0x06},
			expectedErr: InvalidPaddingErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := RemovePkcs7(tt.b, 16)
			if tt.expectedErr != err {
				t.Fatalf("Expected error %s, but got %s", tt.expectedErr, err)
			}

			if !bytes.Equal(tt.expected, actual) {
				t.Fatalf("Expected unpadded bytes %q, but got %q", tt.expected, actual)
			}
		})
	}
}
