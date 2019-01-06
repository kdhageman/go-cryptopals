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

type Encrypt func() (ct []byte, iv []byte, err error)

type Decrypt func(ct []byte) (validPadding bool, error error)

func (d Decrypt) DecryptByteInBlock(target []byte, i int, prev []byte, pt []byte) (byte, error) {
	p := byte(16 - i)
	for j := 0; j < 256; j++ {
		crafted := make([]byte, 16)
		for k := 0; k < 16; k++ {
			crafted[k] = prev[k] ^ pt[k] ^ p
		}
		crafted[i] = byte(j)

		payload := append(crafted, target...)
		valid, err := d(payload)
		if err != nil {
			return 0x00, err
		}
		if valid {
			return byte(j) ^ p ^ prev[i], nil
		}
	}

	return 0x00, NoCandidateErr
}

func (d Decrypt) DecryptBlock(ct []byte, prev []byte) ([]byte, error) {
	pt := bytes.Repeat([]byte{0xff}, 16)
	for i := 15; i >= 0; i-- {
		p, err := d.DecryptByteInBlock(ct, i, prev, pt)
		if err != nil {
			return nil, err
		}
		pt[i] = p
	}
	return pt, nil
}

func oracle() (Encrypt, Decrypt, error) {
	pts, err := readInput()
	if err != nil {
		return nil, nil, err
	}
	key := crypto.RandomKey(aes.BlockSize)
	iv := crypto.RandomKey(aes.BlockSize)

	enc := func() ([]byte, []byte, error) {
		pt := randomPt(pts)
		ct, err := crypto.EncryptCbc(pt, key, iv)
		return ct, iv, err
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

func (c *ch) Solve() error {
	enc, dec, err := oracle()
	var pt byte

	ct, _, err := enc()
	if err != nil {
		return err
	}

	prev := ct[len(ct)-32 : len(ct)-16]
	target := ct[len(ct)-16:]

	for i := 0; i < 256; i++ {
		padbyte := byte(1)
		tamperedBlock := bytes.Repeat([]byte{0xff}, 16)
		tamperedBlock[15] = byte(i)

		payload := append(tamperedBlock, target...)
		valid, err := dec(payload)
		if err != nil {
			return err
		}
		if valid {
			pt = byte(i) ^ padbyte ^ ct[len(ct)-17]
		}
	}
	fmt.Println(pt)

	pt, err = dec.DecryptByteInBlock(target, 15, ct[len(ct)-32:len(ct)-16], bytes.Repeat([]byte{0x00}, 16))
	if err != nil {
		return err
	}
	fmt.Println(pt)

	b, err := dec.DecryptBlock(target, prev)
	if err != nil {
		return err
	}
	fmt.Println(b)
	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
