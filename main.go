package main

import (
	"fmt"
	"github.com/kdhageman/go-cryptopals/challenge/three/twenty"
	"github.com/logrusorgru/aurora"
)

func main() {
	ch := twenty.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
