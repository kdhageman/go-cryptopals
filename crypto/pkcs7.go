package crypto

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/pkg/errors"
)

var (
	BlocksizeErr      = errors.New("block size does not divide data")
	InvalidPaddingErr = errors.New("data has invalid padding")
)

type DataSizeErr struct {
	dsize int
	bsize int
}

func (err DataSizeErr) Error() string {
	return fmt.Sprintf("data block %d larger than block size %d", err.dsize, err.bsize)
}

func PadPkcs7(b []byte, bsize int) []byte {
	padlength := bsize - (len(b) % bsize)
	if padlength == 0 {
		padlength = bsize
	}

	return append(b, bytes.Repeat([]byte{byte(padlength)}, padlength)...)
}

func RemovePkcs7(b []byte, bsize int) ([]byte, error) {
	if len(b)%bsize != 0 {
		return nil, BlocksizeErr
	}
	padbyte := b[len(b)-1]
	if padbyte < 1 || padbyte > aes.BlockSize {
		return nil, InvalidPaddingErr
	}
	padlen := int(padbyte)
	for i := len(b) - 1; i > len(b)-1-padlen; i-- {
		if b[i] != padbyte {
			return nil, InvalidPaddingErr
		}
	}
	return b[:len(b)-padlen], nil
}
