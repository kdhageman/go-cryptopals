package sixteen

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge"
	"github.com/kdhageman/go-cryptopals/crypto"
	"github.com/logrusorgru/aurora"
	"strings"
)

var (
	order = []string{"comment1", "userdata", "comment2"}
)

type User map[string]string

func (u *User) String() string {
	var s []string
	for _, k := range order {
		s = append(s, fmt.Sprintf("%s=%s", k, (*u)[k]))
	}
	return strings.Join(s, ";")
}

func (u *User) IsAdmin() bool {
	admin, ok := (*u)["admin"]
	return ok && admin == "true"
}

func FromUserData(userdata string) User {
	r := strings.NewReplacer(";", "", "=", "")
	userdata = r.Replace(userdata)
	d := map[string]string{}
	d["comment1"] = "cooking%20MCs"
	d["userdata"] = userdata
	d["comment2"] = "%20like%20a%20pound%20of%20bacon"
	return d
}

func FromBytes(b []byte) (User, error) {
	d := map[string]string{}
	parts := strings.Split(string(b), ";")
	for _, part := range parts {
		subparts := strings.Split(part, "=")
		k := subparts[0]
		v := ""
		if len(subparts) > 1 {
			v = subparts[1]
		}
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
	ct, err := enc([]byte(" admin true"))
	if err != nil {
		return err
	}

	semicolon, _ := crypto.Xor([]byte(" "), []byte(";"))
	equals, _ := crypto.Xor([]byte(" "), []byte("="))

	dSemicolon, _ := crypto.Xor(semicolon, []byte{ct[16]})
	dEquals, _ := crypto.Xor(equals, []byte{ct[22]})

	craftedCt := ct[:16]
	craftedCt = append(craftedCt, dSemicolon...)
	craftedCt = append(craftedCt, ct[17:22]...)
	craftedCt = append(craftedCt, dEquals...)
	craftedCt = append(craftedCt, ct[23:]...)

	pt, err := dec(craftedCt)
	if err != nil {
		return err
	}
	d, err := FromBytes(pt)
	if err != nil {
		return err
	}

	fmt.Printf("User is admin: %t\n", aurora.Cyan(d.IsAdmin()))

	return nil
}

func New() challenge.Challenge {
	return &ch{}
}
