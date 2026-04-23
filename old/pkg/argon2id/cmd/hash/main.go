package main

import (
	"fmt"
	"os"
	"syscall"

	//"crypt/rand"
	"crypt/argon2id"

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
	err := argon2id.RunCLI()
	if err != nil {
		fmt.Println(err)
	}
//	pass, err := cli() 
//	if err != nil {
//		fmt.Println(err)
//	}
//	p := internal.NewDefaultParams()
//	// IS Salt vaule(p.saltLength correct?)
//	salt, err := rand.Salt(p.GetSaltLength()) 
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//
//	hashed, err := internal.Hash([]byte(pass), salt, p)
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	fmt.Println(hashed)
}
