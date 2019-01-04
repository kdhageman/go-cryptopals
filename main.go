package main

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge/two/fifteen"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := fifteen.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
