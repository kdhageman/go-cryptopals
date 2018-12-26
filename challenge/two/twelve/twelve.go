package twelve

import (
	"bytes"
	"fmt"
	"github.com/kdhageman/gocrypto/challenge"
	"github.com/kdhageman/gocrypto/crypto"
	"github.com/logrusorgru/aurora"
)

type ch struct{}

func detectBlocksize() (int, error) {
	prefix := []byte{0x41}
	bsize := 0
	var prev []byte
	for i := 1; i < 40; i++ {
		ct, err := crypto.EncryptionOracleConsistent(prefix)
		if err != nil {
			return 0, err
		}
		if prev != nil && bytes.Equal(prev[:i-1], ct[:i-1]) {
			bsize = i - 1
			break
		}
		prev = ct
		prefix = append(prefix, 0x41)
	}
	return bsize, nil
}

func (c *ch) Solve() error {
	// discover block size
	bsize, err := detectBlocksize()
	if err != nil {
		return err
	}
	fmt.Printf("Found block size: %d\n", aurora.Cyan(bsize))

	ct, err := crypto.EncryptionOracleConsistent([]byte{})
	if err != nil {
		return err
	}
	mode := crypto.DetectMode(ct, bsize)
	fmt.Printf("Found encryption mode: %s\n", aurora.Cyan(mode))



	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
