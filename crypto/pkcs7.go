package crypto

import (
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
	if len(b)%bsize == 0 {
		return b
	}

	blocks := InBlocks(b, bsize)
	lastBlock := blocks[len(blocks)-1]
	d := bsize - len(lastBlock)
	for i := 0; i < d; i++ {
		lastBlock = append(lastBlock, byte(d))
	}
	var res []byte
	for i := 0; i < len(blocks)-1; i++ {
		res = append(res, blocks[i]...)
	}
	res = append(res, lastBlock...)

	return res
}

func RemovePkcs7(b []byte, bsize int) ([]byte, error) {
	if len(b)%bsize != 0 {
		return nil, BlocksizeErr
	}
	paddingByte := b[len(b)-1]
	if paddingByte >= aes.BlockSize {
		return b, nil
	}

	for i := 0; i < int(paddingByte); i++ {
		if b[len(b)-1-i] != paddingByte {
			return nil, InvalidPaddingErr
		}
	}

	return b[:len(b)-int(paddingByte)], nil
}
