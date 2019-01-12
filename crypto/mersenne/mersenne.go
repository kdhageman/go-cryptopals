package mersenne

import "errors"

const (
	f = 1812433253
)

var (
	NotSeededErr = errors.New("must seed mersenne twister before retrieving random numbers")
)

type MersenneTwister interface {
	Rand() (int, error)
	Seed(seed int)
}

type Params struct {
	n                    int  // degrees of recurrence
	w                    uint // word size
	m                    int
	r                    uint
	u, s, t              uint
	b, c, d              int
	lowermask, uppermask int
	a                    int
	l                    uint
}

var (
	DefaultParams = Params{
		w: 32,
		n: 624,
		m: 397,
		r: 31,
		s: 7,
		t: 15,
		u: 11,
		b: 0x9d2c5680,
		c: 0xefc60000,
		d: 0xffffffff,
		a: 0x9908b0df,
		l: 18,
	}
)

type mersenneTwister struct {
	params Params
	state  []int
	index  int
}

func (mt *mersenneTwister) twist() {
	for i := 0; i < mt.params.n; i++ {
		x := (mt.state[i] & mt.params.uppermask) + (mt.state[(i+1)%mt.params.n] & mt.params.lowermask)
		xA := x >> 1
		if x%2 != 0 {
			xA = xA ^ mt.params.a
		}
		mt.state[i] = mt.state[(i+mt.params.m)%mt.params.n] ^ xA
	}
	mt.index = 0
}

func (mt *mersenneTwister) Seed(seed int) {
	mt.index = mt.params.n
	mt.state[0] = seed
	for i := 1; i < mt.params.n; i++ {
		mt.state[i] = f*(mt.state[i-1]^(mt.state[i-1]>>(mt.params.w-2))) + i
	}
}

func (mt *mersenneTwister) Rand() (int, error) {
	if mt.index >= mt.params.n {
		if mt.index > mt.params.n {
			return 0, NotSeededErr
		}
		mt.twist()
	}

	y := mt.state[mt.index]
	y ^= (y >> mt.params.u) & mt.params.d
	y ^= (y << mt.params.s) & mt.params.b
	y ^= (y << mt.params.t) & mt.params.c
	y ^= y >> mt.params.l
	mt.index++

	return y, nil
}

func New(params Params) MersenneTwister {
	params.lowermask = 1<<params.r - 1
	params.uppermask = (1<<(params.w-params.r) - 1) << params.r
	return &mersenneTwister{
		params: params,
		state:  make([]int, params.n),
		index:  params.n + 1,
	}
}
