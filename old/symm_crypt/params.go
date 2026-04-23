package symm_crypt 

import (
	"fmt"
	
	"crypt/aes256gcm"
)

type Crypter interface {
	Encrypt(data, key []byte) ([]byte, error)
	Decrypt(data, key []byte) ([]byte, error)
}

type Aes256_gcm struct {
}

func (a Aes256_gcm) Encrypt(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Key length must be 32 bytes")
	}
	key32 := [32]byte(key[:])
	encrypted, err := aes256gcm.Encrypt(key32, data)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (a Aes256_gcm) Decrypt(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("Key length must be 32 bytes")
	}
	key32 := [32]byte(key[:])
	decrypted, err := aes256gcm.Decrypt(key32, data)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

type InvalidCrypter struct {}

func (i InvalidCrypter) Encrypt(data, key []byte) ([]byte, error) {
	return nil, fmt.Errorf("Invalid crypter")
}
func (i InvalidCrypter) Decrypt(data, key []byte) ([]byte, error) {
	return nil, fmt.Errorf("Invalid crypter")
}

func Parse(args []string) (Crypter, error) {
	counter := 0
	crypterString := ""
	for _, arg := range args {
		if arg[:9] == "--crypter=" {
			counter++
			crypterString = arg[9:]
		}
	}
	if counter == 0 {
		return Aes256_gcm{}, nil // Default
	}
	if counter == 1 {
		if crypterString == "aes256gcm" {
			return Aes256_gcm{}, nil
		}
	}
	return InvalidCrypter{}, fmt.Errorf("More than one crypter parameter")
}
