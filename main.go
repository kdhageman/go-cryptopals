package main

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge/two/eleven"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := eleven.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
