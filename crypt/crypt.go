package crypt 

import (
	"fmt"
	"crypt/aes256gcm"
	"crypt/chacha20poly1305"
)

func Encrypt(symmCryptFunc string, key, data []byte) ([]byte, error) {
	switch symmCryptFunc {
	case "aes256gcm":
		encrypted, err := aes256gcm.Encrypt(key, data)
		if err != nil {
			return nil, err
		}
		return encrypted, nil
	case "chacha20poly1305":
		encrypted, err := chacha20poly1305.Encrypt(key, data)
		if err != nil {
			return nil, err
		}
		return encrypted, nil
	}
	return nil, fmt.Errorf("Invalid type of symetric encryption function") 
}

func Decrypt(symmCryptFunc string, key []byte, encrypted []byte) ([]byte, error) {
	switch symmCryptFunc {
	case "aes256gcm":
		decrypted, err := aes256gcm.Decrypt(key, encrypted)
		if err != nil {
			return nil, err
		}
		return decrypted, nil
	case "chacha20poly1305":
		decrypted, err := chacha20poly1305.Decrypt(key, encrypted)
		if err != nil {
			return nil, err
		}
		return decrypted, nil
	}
	return nil, fmt.Errorf("Ivalid type of symetric function") 
}



