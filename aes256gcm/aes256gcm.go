package aes256gcm 

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"crypto/rand"
)

func Encrypt(key32 [32]byte, data []byte) ([]byte, error) {
	sealed := []byte{}
	key := []byte{}
	key = key32[:]
	for k, v := range key32 {
		key[k] = v
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return sealed, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return sealed, err
	}
	// TODO : consider other ways of creating nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return sealed, err
	}
	sealed = aesGCM.Seal(nonce, nonce, data, nil)
	return sealed, nil
}

func Decrypt(key32 [32]byte, data []byte) ([]byte, error) {
	decrypted := []byte{} 
	key := []byte{}
	key = key32[:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return decrypted, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return decrypted, err
	}
	nonceSize := aesGCM.NonceSize()
	// TODO: may be rename ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decrypted, err = aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return decrypted, err
	}
	return decrypted, nil
}
