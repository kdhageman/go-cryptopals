package main

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge/six"
)

func main() {
	ch := six.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf(err.Error())
	}
}
