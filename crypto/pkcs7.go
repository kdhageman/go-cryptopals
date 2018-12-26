package crypto

import (
	"fmt"
)

type DataSizeErr struct {
	dsize int
	bsize int
}

func (err DataSizeErr) Error() string {
	return fmt.Sprintf("data block %d larger than block size %d", err.dsize, err.bsize)
}

func PadPkcs7(b []byte, bsize int) ([]byte, error) {
	if len(b) > bsize {
		return nil, DataSizeErr{len(b), bsize}
	}
	if len(b) == bsize {
		return b, nil
	}
	d := bsize - len(b)
	for i := 0; i < d; i++ {
		b = append(b, byte(d))
	}
	return b, nil
}
