package rand 

import (
	"YSNP2/rand/internal"
)

func Salt(size uint32) ([]byte, error) {
	salt, err := internal.NewSalt(size)
	if err != nil {
		return nil, err
	}
	return salt, err 
}
