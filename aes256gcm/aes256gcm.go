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

func EncryptPtr(key, nonce, plainData, cipherData []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("Key length is not 32 bytes")
	}
	sealed := []byte{}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(nonce) != aesGCM.NonceSize() {
		return fmt.Errorf("Invalid Nonce size, should be: %d , got: %d", aesGCM.NonceSize(), len(nonce))
	}
	if len(cipherData) < len(plainData) + aesGCM.Overhead() {
		return fmt.Errorf("Cipherdata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(plainData) + aesGCM.Overhead()), len(cipherData))
	}
	newCipherData = aesGCM.Seal(cipherData[:0], nonce, plainData, nil)
	return nil
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


func DecryptPtr(key, nonce, cipherData, plainData []byte) error {
	//decrypted := []byte{} 
	if len(key) != 32 {
		return fmt.Errorf("Key length is not 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(nonce) != aesGCM.NonceSize() {
		return fmt.Errorf("Invalid Nonce size, should be: %d , got: %d", aesGCM.NonceSize(), len(nonce))
	}
	if len(plainData) < len(cipherData) + aesGCM.Overhead() {
		return fmt.Errorf("Plaindata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(cipherData) + aesGCM.Overhead()), len(plainData))
	}
	newPlainData, err = aesGCM.Open(plainData, nonce, cipherData, nil)
	return err
}
