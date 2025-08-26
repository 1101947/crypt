package main

import (
	"pdk/internal"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
)

func cli() (string, error) {
	args := os.Args
	pass := ""
	if len(args) > 2 {
		return pass, fmt.Errorf("Must have one or no arguments")
	} else if len(args) == 2 {
		return args[1], nil
	} else {
		passBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		pass = string(passBytes)
		return pass, nil
	}
}

func main() {
	pass, err := cli() 
	if err != nil {
		fmt.Println(err)
	}
	p := internal.NewParams()
	hashed, err := internal.Hash([]byte(pass), p)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(hashed)
}
