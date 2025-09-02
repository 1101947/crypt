package rand 

import (
	"fmt"

	"crypt/rand/internal"
)

func Salt(size uint32) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errof("Salt size must be grater than zero")
	}
	salt, err := internal.NewSalt(size)
	if err != nil {
		return nil, err
	}
	return salt, err 
}
