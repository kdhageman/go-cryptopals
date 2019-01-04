package main

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge/two/fourteen"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := fourteen.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
