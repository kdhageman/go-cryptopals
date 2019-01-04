package sixteen

import (
	"errors"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"strings"
)

var (
	InvalidDataErr = errors.New("part must contain a single '=' character")

	order = []string{"comment1", "userdata", "comment2"}
)

type Data map[string]string

func (d *Data) String() string {
	var s []string
	for _, k := range order {
		s = append(s, fmt.Sprintf("%s=%s", k, (*d)[k]))
	}
	return strings.Join(s, ";")
}

func (d *Data) IsAdmin() bool {
	admin, ok := (*d)["admin"]
	return ok && admin == "true"
}

func FromUserData(userdata string) Data {
	r := strings.NewReplacer(";", "", "=", "")
	userdata = r.Replace(userdata)
	d := map[string]string{}
	d["comment1"] = "cooking%20MCs"
	d["userdata"] = userdata
	d["comment2"] = "%20like%20a%20pound%20of%20bacon"
	return d
}

func FromBytes(b []byte) (Data, error) {
	d := map[string]string{}
	parts := strings.Split(string(b), ";")
	for _, part := range parts {
		subparts := strings.Split(part, "=")
		if len(subparts) != 2 {
			return nil, InvalidDataErr
		}
		k, v := subparts[0], subparts[1]
		d[k] = v
	}
	return d, nil
}

func oracle() (crypto.Oracle, crypto.Oracle) {
	key := crypto.RandomKey(16)
	iv := crypto.RandomKey(16)

	encryptor := func(userdata []byte) ([]byte, error) {
		d := FromUserData(string(userdata))
		pt := []byte(d.String())
		return crypto.EncryptCbc(pt, key, iv)
	}
	decryptor := func(ct []byte) ([]byte, error) {
		return crypto.DecryptCbc(ct, key, iv)
	}
	return encryptor, decryptor
}

type ch struct{}

func (c *ch) Solve() error {
	enc, dec := oracle()
	ct, err := enc([]byte("yea"))
	if err != nil {
		return err
	}
	pt, err := dec(ct)
	if err != nil {
		return err
	}
	d, err := FromBytes(pt)
	if err != nil {
		return err
	}
	fmt.Println(d.String())

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
