package main

import (
	"fmt"

	"crypt/pkg/json"
)

func main() {
	_, err := json.Parse("string string string yet another")
	if err != nil {
		fmt.Println(err)
	}
}
