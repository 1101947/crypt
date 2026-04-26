package aes256gcm 

import (
	"io"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func Encrypt(key, data []byte) ([]byte, error) {
	sealed := []byte{}
	block, err := aes.NewCipher(key)
	if err != nil {
		return sealed, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return sealed, err
	}
	//nonce := make([]byte, aesGCM.NonceSize())
	nonce := make([]byte, aesGCM.NonceSize(), aesGCM.NonceSize()+len(data)+aesGCM.Overhead())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return sealed, err
	}
	sealed = aesGCM.Seal(nonce, nonce, data, nil)
	return sealed, nil
}

func Decrypt(key, data []byte) ([]byte, error) {
	decrypted := []byte{} 
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
