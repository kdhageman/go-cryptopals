package crypto

import (
	"bytes"
	"github.com/logrusorgru/aurora"
	"math/rand"
	"testing"
)

func oracle(secret []byte) Oracle {
	key := RandomKey(16)

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
			f := oracle(tt.secret)
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
