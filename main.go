package main

import (
	"fmt"
	"github.com/kdhageman/gocrypto/challenge/two/nine"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := nine.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
