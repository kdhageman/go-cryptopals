package mersenne

import (
	"errors"
	"encoding/binary"
	)

const (
	n = 624
)

var (
	NotSeededErr = errors.New("must seed mersenne twister before retrieving random numbers")
)

type MersenneTwister interface {
	Rand() (int32, error)
	Seed(seed int)
}

type mersenneTwister struct {
	state  []uint32
	index  int
	seeded bool
}

func (mt *mersenneTwister) twist() {
	for i := 0; i < n; i++ {
		x := (mt.state[i] & 0x80000000) + (mt.state[(i+1)%n] & 0x7fffffff)
		xA := x >> 1
		if x%2 != 0 {
			xA = xA ^ 0x9908b0df
		}
		mt.state[i] = mt.state[(i+397)%n] ^ xA
	}
	mt.index = 0
}

func (mt *mersenneTwister) Seed(seed int) {
	mt.index = n
	mt.state[0] = uint32(seed)
	for i := 1; i < n; i++ {
		mt.state[i] = uint32(1812433253*(uint64(mt.state[i-1])^(uint64(mt.state[i-1])>>30)) + uint64(i))
	}
	mt.seeded = true
}

func (mt *mersenneTwister) Rand() (int32, error) {
	if !mt.seeded {
		return 0, NotSeededErr
	}
	if mt.index >= n {
		mt.twist()
	}

	y := uint64(mt.state[mt.index])
	y ^= (y >> 11) & 0xffffffff
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	mt.index++

	return int32(y), nil
}

func FromSlice(state []uint32) MersenneTwister {
	return &mersenneTwister{
		state:  state,
		index:  0,
		seeded: true,
	}
}

func New() MersenneTwister {
	return &mersenneTwister{
		state: make([]uint32, n),
	}
}

type Cipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

type cipher struct {
	key int
	mt MersenneTwister
	ks []byte
}

func intToBytes(a int32) []byte {
	var res []byte
	for i:=0; i<4; i++ {
		res = append([]byte{byte(a % 256)}, res...)
			a = a >> 8
	}
	return res
}

func (c *cipher) next() (byte, error) {
	if len(c.ks) == 0 {
		r, err := c.mt.Rand()
		if err != nil {
			return 0x00, err
		}
		c.ks = intToBytes(r)
	}
	r := c.ks[0]
	c.ks = c.ks[1:]
	return r, nil
}

func (c *cipher) Encrypt(pt []byte) ([]byte, error) {
	c.mt.Seed(c.key)

	var ct []byte
	for _, ptByte := range pt {
		b, err := c.next()
		if err != nil {
			return nil, err
		}
		ct = append(ct, ptByte ^ b)
	}

	return ct, nil
}

func (c *cipher) Decrypt(ct []byte) ([]byte, error) {
	return c.Encrypt(ct)
}

func NewCipher(key []byte) Cipher {
	keyInt := binary.LittleEndian.Uint32(key)
	return &cipher{
		key: int(keyInt),
		mt: New(),
	}
}