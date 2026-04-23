package main

import (
	"fmt"

	"crypt/crypt/symm/encrypt"
)

func main() {
	str, err := encrypt.ProcessEncryption()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(str)
}
