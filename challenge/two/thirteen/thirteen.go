package thirteen

import (
	"bytes"
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
	"net/url"
	"strings"
)

type profile map[string]string

func decode(s string) (profile, error) {
	v, err := url.ParseQuery(s)
	if err != nil {
		return nil, err
	}
	p := map[string]string{}
	for _, el := range []string{"email", "uid", "role"} {
		p[el] = v.Get(el)
	}
	return p, nil
}

func decrypt(ct []byte, key []byte) (profile, error) {
	pt, err := crypto.DecryptEcb(ct, key)
	if err != nil {
		return nil, err
	}
	return decode(string(pt))
}

func (v profile) encode() string {
	var els []string
	for _, el := range []string{"email", "uid", "role"} {
		els = append(els, fmt.Sprintf("%s=%s", el, v[el]))
	}
	return strings.Join(els, "&")
}

func (v profile) encrypt(key []byte) ([]byte, error) {
	pt := []byte(v.encode())
	return crypto.EncryptEcb(pt, key)
}

func profileFor(email string) profile {
	r := strings.NewReplacer("&", "", "=", "")
	email = r.Replace(email)
	return map[string]string{
		"email": email,
		"uid":   "10",
		"role":  "user",
	}
}

type Decryptor func([]byte) (profile, error)

func oracle() (crypto.Oracle, Decryptor) {
	key := crypto.RandomKey(16)
	e := func(pt []byte) ([]byte, error) {
		p := profileFor(string(pt))
		return p.encrypt(key)
	}
	d := func(ct []byte) (profile, error) {
		return decrypt(ct, key)
	}
	return e, d
}

type ch struct{}

func (c *ch) Solve() error {
	e, d := oracle()

	padding := bytes.Repeat([]byte{0xff}, 10)

	padding = append(padding, []byte("admin")...)
	padding = append(padding, bytes.Repeat([]byte{0x11}, 11)...)

	adminCt, err := e(padding)
	if err != nil {
		return err
	}

	padding = bytes.Repeat([]byte{0xff}, 13)
	baseCt, err := e(padding)
	if err != nil {
		return err
	}

	tamperedCt := append(baseCt[:32], adminCt[16:32]...)

	p, err := d(tamperedCt)
	fmt.Printf("Role of profile: %s\n", aurora.Cyan(p["role"]))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
