package crypto

import (
	"bytes"
	"github.com/logrusorgru/aurora"
	"math/rand"
	"testing"
)

func oracle(secret []byte, ksize int) Oracle {
	key := RandomKey(ksize)

	f := func(pt []byte) ([]byte, error) {
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
			f := oracle(tt.secret, 16)
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
			o := oracle([]byte("abcdefghijklmnopqrstuvwxyz"), tt.bsize)

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
