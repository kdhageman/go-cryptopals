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
			pt, err := PaddingOracleAttack(f)
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
				t.Fatalf("Expected cipher text %q, but got %q", tt.expected, ct)
			}
		})
	}
}
