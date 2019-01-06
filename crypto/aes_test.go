package crypto

import (
	"bytes"
	"github.com/logrusorgru/aurora"
	"math/rand"
	"testing"
)

func oracle(secret []byte, prefix []byte, ksize int) Oracle {
	key := RandomKey(ksize)

	f := func(pt []byte) ([]byte, error) {
		pt = append(prefix, pt...)
		pt = append(pt, secret...)
		ct, err := EncryptEcb(pt, key)
		if err != nil {
			return nil, err
		}
		return ct, nil
	}

	return f
}

func TestPaddingOracleAttack(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
	}{
		{
			name:   "Non-dividing block size",
			secret: []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		},
		{
			name:   "Dividing block size",
			secret: []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"),
		},
		{
			name:   "Incomplete block",
			secret: []byte("abc"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := oracle(tt.secret, []byte(""), 16)
			pt, err := EbcPaddingOracleAttack(f)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if !bytes.Equal(pt, tt.secret) {
				t.Fatalf("Expected %s, but got %s", aurora.Cyan(tt.secret), aurora.Cyan(pt))
			}
		})
	}
}

func TestEcb(t *testing.T) {
	var pt []byte
	for _, b := range rand.Perm(2048) {
		pt = append(pt, byte(b))
	}
	key := RandomKey(16)
	ct, err := DecryptEcb(pt, key)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	newPt, err := EncryptEcb(ct, key)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if !bytes.Equal(pt, newPt) {
		t.Fatalf("Expected new plain text %q to equal old plain text %q", aurora.Cyan(newPt), aurora.Cyan(pt))
	}

}

func TestDetectBlocksize(t *testing.T) {
	tests := []struct {
		name  string
		bsize int
	}{
		{
			name:  "Block size of 16",
			bsize: 16,
		},
		{
			name:  "Block size of 24",
			bsize: 24,
		},
		{
			name:  "Block size of 32",
			bsize: 32,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := oracle([]byte("abcdefghijklmnopqrstuvwxyz"), []byte(""), tt.bsize)

			actual, err := DetectBlocksize(o)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if actual != tt.bsize {
				t.Fatalf("Expected block size %d, but got %d", tt.bsize, actual)
			}
		})
	}
}

func TestDetectPrefixSize(t *testing.T) {
	tests := []struct {
		name  string
		bsize int
		psize int
	}{
		{
			name:  "bsize 16, psize 7",
			bsize: 16,
			psize: 7,
		},
		{
			name:  "bsize 16, psize 16",
			bsize: 16,
			psize: 16,
		},
		{
			name:  "bsize 16, psize 0",
			bsize: 16,
			psize: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := RandomKey(tt.psize)
			o := oracle([]byte(""), prefix, tt.bsize)
			actual, err := DetectPrefixSize(o, tt.bsize)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}

			if actual != tt.psize {
				t.Fatalf("Expected prefix size %d, but got %d", tt.psize, actual)
			}
		})
	}
}

func TestEncryptEcb(t *testing.T) {
	tests := []struct {
		name     string
		pt       []byte
		key      []byte
		expected []byte
	}{
		{
			name:     "16 byte key",
			pt:       []byte("aaaaaaaaaaaaaaaa"),
			key:      []byte("aaaaaaaaaaaaaaaa"),
			expected: []byte{0x51, 0x88, 0xc6, 0x47, 0x4b, 0x22, 0x8c, 0xbd, 0xd2, 0x42, 0xe9, 0x12, 0x5e, 0xbe, 0x1d, 0x53},
		},
		{
			name:     "24 byte key",
			pt:       []byte("aaaaaaaaaaaaaaaa"),
			key:      []byte("aaaaaaaaaaaaaaaaaaaaaaaa"),
			expected: []byte{0xb6, 0x07, 0x00, 0x28, 0x4e, 0xcb, 0xa5, 0x9f, 0xa2, 0x49, 0x62, 0xd0, 0x0c, 0xf9, 0xc2, 0x99},
		},
		{
			name:     "32 byte key",
			pt:       []byte("aaaaaaaaaaaaaaaa"),
			key:      []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			expected: []byte{0x2c, 0xcd, 0x45, 0x89, 0x6f, 0xc3, 0x52, 0x5e, 0x03, 0xc7, 0xcb, 0x97, 0xb6, 0x68, 0x95, 0xff},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := EncryptEcb(tt.pt, tt.key)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if !bytes.Equal(ct, tt.expected) {
				t.Fatalf("Expected cipher text %x, but got %x", aurora.Cyan(tt.expected), aurora.Cyan(ct))
			}
		})
	}
}

func TestEncryptCbc(t *testing.T) {
	tests := []struct {
		name     string
		pt       []byte
		key      []byte
		iv       []byte
		expected []byte
	}{
		{
			name:     "16 byte key",
			pt:       []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			key:      []byte("aaaaaaaaaaaaaaaa"),
			iv:       bytes.Repeat([]byte{0x00}, 16),
			expected: []byte{0x51, 0x88, 0xc6, 0x47, 0x4b, 0x22, 0x8c, 0xbd, 0xd2, 0x42, 0xe9, 0x12, 0x5e, 0xbe, 0x1d, 0x53, 0x1c, 0xc9, 0x47, 0x6d, 0xe0, 0x92, 0x39, 0x87, 0x28, 0xf0, 0xd7, 0x85, 0xf8, 0x48, 0x46, 0xe8},
		},
		{
			name:     "32 byte key",
			pt:       []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			key:      []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			iv:       bytes.Repeat([]byte{0x00}, 16),
			expected: []byte{0x2c, 0xcd, 0x45, 0x89, 0x6f, 0xc3, 0x52, 0x5e, 0x03, 0xc7, 0xcb, 0x97, 0xb6, 0x68, 0x95, 0xff, 0xd5, 0x6b, 0x1e, 0x96, 0x5b, 0x58, 0xde, 0x59, 0x19, 0xcd, 0xb8, 0xbc, 0x55, 0x90, 0x9e, 0xad},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := EncryptCbc(tt.pt, tt.key, tt.iv)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if !bytes.Equal(ct, tt.expected) {
				t.Fatalf("Expected cipher text %x, but got %x", aurora.Cyan(tt.expected), aurora.Cyan(ct))
			}
		})
	}
}

func TestDecryptCbc(t *testing.T) {
	tests := []struct {
		name     string
		ct       []byte
		key      []byte
		iv       []byte
		expected []byte
	}{
		{
			name:     "16 byte key",
			ct:       []byte{0x51, 0x88, 0xc6, 0x47, 0x4b, 0x22, 0x8c, 0xbd, 0xd2, 0x42, 0xe9, 0x12, 0x5e, 0xbe, 0x1d, 0x53, 0x1c, 0xc9, 0x47, 0x6d, 0xe0, 0x92, 0x39, 0x87, 0x28, 0xf0, 0xd7, 0x85, 0xf8, 0x48, 0x46, 0xe8},
			key:      []byte("aaaaaaaaaaaaaaaa"),
			iv:       bytes.Repeat([]byte{0x00}, 16),
			expected: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		},
		{
			name:     "32 byte key",
			ct:       []byte{0x2c, 0xcd, 0x45, 0x89, 0x6f, 0xc3, 0x52, 0x5e, 0x03, 0xc7, 0xcb, 0x97, 0xb6, 0x68, 0x95, 0xff, 0xd5, 0x6b, 0x1e, 0x96, 0x5b, 0x58, 0xde, 0x59, 0x19, 0xcd, 0xb8, 0xbc, 0x55, 0x90, 0x9e, 0xad},
			key:      []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			iv:       bytes.Repeat([]byte{0x00}, 16),
			expected: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := DecryptCbc(tt.ct, tt.key, tt.iv)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if !bytes.Equal(ct, tt.expected) {
				t.Fatalf("Expected cipher text %x, but got %x", aurora.Cyan(tt.expected), aurora.Cyan(ct))
			}
		})
	}
}

func TestCBC(t *testing.T) {
	original := "some kind of somewhat long plain text!"

	pt := []byte(original)
	key := bytes.Repeat([]byte{0x90}, 16)
	iv := bytes.Repeat([]byte{0x90}, 16)

	ct, err := EncryptCbc(pt, key, iv)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	actual, err := DecryptCbc(ct, key, iv)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if string(actual) != original {
		t.Fatalf("Expected encrypted string %s, but got %s", aurora.Cyan(original), aurora.Cyan(string(actual)))
	}
}

func TestIntToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected []byte
	}{
		{
			name:     "Single byte",
			input:    127,
			expected: []byte{127},
		},
		{
			name:     "Two bytes",
			input:    257,
			expected: []byte{1, 1},
		},
		{
			name:     "Three bytes",
			input:    65793,
			expected: []byte{1, 1, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := IntToBytes(tt.input)
			if !bytes.Equal(tt.expected, actual) {
				t.Fatalf("Expected bytes %x, but got %x", tt.expected, actual)
			}
		})
	}
}

func TestReverse(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "Single byte",
			input:    []byte{1},
			expected: []byte{1},
		},
		{
			name:     "Even number of bytes",
			input:    []byte{1, 2, 3, 4},
			expected: []byte{4, 3, 2, 1},
		},
		{
			name:     "Uneven number of bytes",
			input:    []byte{1, 2, 3, 4, 5},
			expected: []byte{5, 4, 3, 2, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Reverse(tt.input)
			if !bytes.Equal(tt.expected, actual) {
				t.Fatalf("Expected bytes %x, but got %x", tt.expected, actual)
			}
		})
	}
}
