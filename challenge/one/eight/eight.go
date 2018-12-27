package eight

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
	"math"
	"os"
)

const (
	BlockSize = 16
)

type ch struct{}

func (c *ch) Solve() error {
	f, err := os.Open("challenge/eight/input.txt")
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	unique := math.MaxInt16
	var ecbBlock []byte
	for scanner.Scan() {
		line := scanner.Text()
		ct, err := hex.DecodeString(line)
		if err != nil {
			return err
		}

		dist := map[string]int{}
		blocks := crypto.InBlocks(ct, BlockSize)
		curUnique := 0
		for _, b := range blocks {
			s := string(b)
			if _, ok := dist[s]; !ok {
				dist[s] = 0
				curUnique++
			}
			dist[s]++
		}
		if curUnique < unique {
			unique = curUnique
			ecbBlock = ct
		}
	}
	fmt.Printf("Duplicate block count: %d\n", aurora.Cyan(16-unique))
	fmt.Printf("AES encrypted block: %s\n", aurora.Cyan(hex.EncodeToString(ecbBlock)))
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
