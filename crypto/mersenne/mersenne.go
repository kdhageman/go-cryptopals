package mersenne

import "errors"

const (
	n = 624
)

var (
	NotSeededErr = errors.New("must seed mersenne twister before retrieving random numbers")
)

type MersenneTwister interface {
	Rand() (int32, error)
	Seed(seed uint32)
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

func (mt *mersenneTwister) Seed(seed uint32) {
	mt.index = n
	mt.state[0] = seed
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

func New() MersenneTwister {
	return &mersenneTwister{
		state: make([]uint32, n),
	}
}
