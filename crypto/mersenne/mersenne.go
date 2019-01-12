package mersenne

const (
	f = 1812433253
)

type MersenneTwister interface {
	Rand() int
	Seed(seed int) error
}

type Params struct {
	n                    int  // degrees of recurrence
	w                    uint // word size
	r                    uint
	u, s, t              uint
	b, c, d              int
	lowermask, uppermask int
}

var (
	DefaultParams = Params{
		w: 32,
		n: 624,
		r: 31,
		s: 7,
		t: 15,
		u: 11,
		b: 0x9d2c5680,
		c: 0xefc60000,
		d: 0xffffffff,
	}
)

type mersenneTwister struct {
	params Params
	state  []int
	index  int
}

func (mt *mersenneTwister) twist() {
	// todo: implement
}

func (mt *mersenneTwister) Seed(seed int) error {
	mt.index = mt.params.n
	mt.state[0] = seed
	for i := 1; i < mt.params.n; i++ {
		v := f*(mt.state[i-1]^(mt.state[i-1]>>(mt.params.w-2))) + i
		mt.state[i] = v & (1<<mt.params.w - 1)
	}
	return nil
}

func (mt *mersenneTwister) Rand() int {
	if mt.index >= mt.params.n {
		if mt.index > mt.params.n {
			mt.Seed(5489)
		}
		mt.twist()
	}

	y := mt.state[mt.index]
	y = y ^ ((y >> mt.params.u) & mt.params.d)
	y = y ^ ((y << mt.params.s) & mt.params.b)
	y = y ^ ((y << mt.params.t) & mt.params.c)
	y = y ^ (y >> 1)

	mt.index++

	return y & (1<<mt.params.w - 1)
}

func New(params Params) MersenneTwister {
	params.lowermask = 1<<params.r - 1
	params.uppermask = (1<<(params.w-params.r) - 1) << params.r
	return &mersenneTwister{
		params: params,
		state:  make([]int, params.n),
	}
}
