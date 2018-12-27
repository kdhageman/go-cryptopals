package crypto

import (
	"bytes"
	"github.com/logrusorgru/aurora"
	"testing"
)

var (
	secret = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func oracle() func([]byte) ([]byte, error) {
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
	f := oracle()
	pt, err := PaddingOracleAttack(f)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if !bytes.Equal(pt, secret) {
		t.Fatalf("Expected %s, but got %s", aurora.Cyan(secret), aurora.Cyan(pt))
	}

}
