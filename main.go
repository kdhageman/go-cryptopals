package main

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge/seven"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := seven.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
