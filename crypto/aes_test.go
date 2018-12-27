package crypto

import (
	"bytes"
	"github.com/logrusorgru/aurora"
	"testing"
)

func oracle(secret []byte) func([]byte) ([]byte, error) {
	key := RandomKey(16)

	f := func(prefix []byte) ([]byte, error) {
		pt := append(prefix, secret...)
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
