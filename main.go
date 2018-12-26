package main

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge/two/ten"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := ten.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
