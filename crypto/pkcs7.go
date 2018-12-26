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
