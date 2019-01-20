package main

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/kdhageman/go-cryptopals/challenge/three/twentyfour"
)

func main() {
	ch := twentyfour.New()
	if err := ch.Solve(); err != nil {
		fmt.Printf("Failed to solve challenge: %s", aurora.Red(err.Error()))
	}
}
