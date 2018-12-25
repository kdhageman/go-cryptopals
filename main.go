package main

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge/four"
)

func main() {
	ch := four.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf(err.Error())
	}
}