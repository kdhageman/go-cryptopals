package main

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge/two/twelve"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := twelve.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
