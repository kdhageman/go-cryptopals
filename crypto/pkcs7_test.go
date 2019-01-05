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
			name:     "Block size divides data",
			b:        []byte("aaaaaa"),
			bsize:    3,
			expected: append([]byte("aaaaaa"), 0x03, 0x03, 0x03),
		},
		{
			name:     "Padding within single block",
			b:        []byte("aa"),
			bsize:    4,
			expected: append([]byte("aa"), 0x02, 0x02),
		},
		{
			name:     "Padding of multiple blocks",
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
	dbyte := []byte{0x94}

	tests := []struct {
		name        string
		b           []byte
		expected    []byte
		expectedErr error
	}{
		{
			name:     "Valid",
			b:        append(bytes.Repeat(dbyte, 10), bytes.Repeat([]byte{6}, 6)...),
			expected: bytes.Repeat(dbyte, 10),
		},
		{
			name:     "Blocksize divides data",
			b:        append(bytes.Repeat(dbyte, 16), bytes.Repeat([]byte{16}, 16)...),
			expected: bytes.Repeat(dbyte, 16),
		},
		{
			name:        "Invalid block size",
			b:           append(bytes.Repeat(dbyte, 11), bytes.Repeat([]byte{6}, 6)...),
			expectedErr: BlocksizeErr,
		},
		{
			name:        "Too short padding",
			b:           append(bytes.Repeat(dbyte, 11), bytes.Repeat([]byte{6}, 5)...),
			expectedErr: InvalidPaddingErr,
		},
		{
			name:        "No padding",
			b:           bytes.Repeat(dbyte, 16),
			expectedErr: InvalidPaddingErr,
		},
		{
			name:        "Zero value padding",
			b:           append(bytes.Repeat(dbyte, 15), 0x00),
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
