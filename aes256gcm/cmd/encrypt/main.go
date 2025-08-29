package main 

import (
	"fmt"
	"aes256-gcm/internal"
	"os"
)

func cli() ([32]byte, []byte, error) {
	key := [32]byte{}
	data := []byte{}
	args := os.Args
	if len(args) != 3 {
		return key, data, fmt.Errorf("Must have 2 arguments")
	}
	copy(key[:], args[1])
	data = []byte(args[2])
	return key, data, nil
}

func main() {
	key, data, err := cli()
	if err != nil {
		fmt.Println(err)
		return 
	}
	encrypted, err := internal.Encrypt(key, data)
	if err != nil {
		fmt.Println(err)
		return 
	}
	fmt.Printf("%v\n", encrypted)
}
