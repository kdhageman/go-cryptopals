package main

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge/five"
)

func main() {
	ch := five.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf(err.Error())
	}
}
