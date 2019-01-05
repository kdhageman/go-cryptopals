package seventeen

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"math"
	"math/rand"
	"os"
)

var (
	MultipleCandidateErr = errors.New("found multiple candidates for plain text byte")
	NoCandidateErr       = errors.New("found no candidates for plain text byte")
)

func init() {
	//rand.Seed(time.Now().Unix())
}

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
type Decryptor func(ct []byte) (validPadding bool, error error)

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
		if err != nil {
			if err == crypto.InvalidPaddingErr || err == crypto.BlocksizeErr {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
	return enc, dec, nil
}

type ch struct{}

//func DecryptBlock(ct []byte, dec Decryptor) ([]byte, error) {
//	var pt []byte
//	for i:=0; i<aes.BlockSize; i++ {
//		b, err := DecryptByteInBlock(ct, i, dec)
//		if err != nil {
//			return nil, err
//		}
//		pt = append(pt, b)
//	}
//	return pt, nil
//}

func DecryptByteInBlock(ct []byte, j int, dec Decryptor) (byte, error) {
	var candidates []byte
	for i := 0; i <= math.MaxUint8; i++ {
		tampered := bytes.Repeat([]byte{0xe0}, j)
		tampered = append(tampered, byte(i))
		tampered = append(tampered, bytes.Repeat([]byte{byte(16 - j)}, 15-j)...)

		validPadding, err := dec(append(tampered, ct...))
		if err != nil {
			return 0x00, err
		}
		if validPadding {
			ptByte, err := crypto.Xor([]byte{byte(i)}, []byte{byte(16 - j)})
			if err != nil {
				return 0x00, err
			}
			candidates = append(candidates, ptByte...)
		}
	}
	switch len(candidates) {
	case 0:
		return 0x00, NoCandidateErr
	case 1:
		return candidates[0], nil
	default:
		return 0x00, MultipleCandidateErr
	}
}

func (c *ch) Solve() error {
	enc, dec, err := oracle()
	var pt []byte

	ct, err := enc()
	if err != nil {
		return err
	}

	// todo: all blocks
	// todo: all bytes in block
	b, err := DecryptByteInBlock(ct[:16], 15, dec)
	if err != nil {
		return err
	}
	pt = append([]byte{b}, pt...)
	fmt.Println(pt)

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
