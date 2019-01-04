package seventeen

import (
	"bufio"
	"encoding/base64"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"math/rand"
	"os"
)

func readInput() ([][]byte, error) {
	f, err := os.Open("challenge/three/seventeen/input.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var res [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		b, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, nil
}

func randomPt(pts [][]byte) []byte {
	i := rand.Intn(len(pts))
	return pts[i]
}

type Encryptor func() ([]byte, error)
type Decryptor func(ct []byte) (bool, error)

func oracle() (Encryptor, Decryptor, error) {
	pts, err := readInput()
	if err != nil {
		return nil, nil, err
	}
	key := crypto.RandomKey(16)
	iv := crypto.RandomKey(16)

	enc := func() ([]byte, error) {
		pt := randomPt(pts)
		return crypto.EncryptCbc(pt, key, iv)
	}
	dec := func(ct []byte) (bool, error) {
		_, err := crypto.DecryptCbc(ct, key, iv)
		if err == crypto.InvalidPaddingErr || err == crypto.BlocksizeErr {
			return false, nil
		}
		return true, nil
	}
	return enc, dec, nil
}

type ch struct{}

func (c *ch) Solve() error {
	_, _, err := oracle()
	if err != nil {
		return err
	}

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
