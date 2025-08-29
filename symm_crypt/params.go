package symm_crypt 

import (
	"fmt"
	
	"YSNP2/aes256gcm"
)

type Aes256_gcm struct {
}

type Crypter interface {
	Encrypt(data, key []byte) ([]byte, error)
	Decrypt(data, key []byte) ([]byte, error)
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

