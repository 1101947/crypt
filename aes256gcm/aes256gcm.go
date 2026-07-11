package aes256gcm 

import (
	//"io"
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	//"crypto/rand"
)

// key must be 32bytes
// nonce at least 12bytes
type AES256GCM bool

func GetAES256GCM() AES256GCM {
	return AES256GCM(true)
}

func (A AES256GCM) Encrypt(key, nonce, plainData, cipherData []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	// only for the first and last one
	if len(nonce) != aesGCM.NonceSize() {
		return fmt.Errorf("Invalid Nonce size, should be: %d , got: %d", aesGCM.NonceSize(), len(nonce))
	}

	// only for the first and last one
	if len(cipherData) < len(plainData) + aesGCM.Overhead() {
		return fmt.Errorf("Cipherdata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(plainData) + aesGCM.Overhead()), len(cipherData))
	}
	// cipherdata is writen to cipherData passed as first argument
	_ = aesGCM.Seal(cipherData[:0], nonce, plainData, nil)
	return nil
}

func (A AES256GCM) Decrypt(key, nonce, cipherData, plainData []byte) error {
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
	//if len(plainData) < len(cipherData) + aesGCM.Overhead() {
	if len(plainData) < len(cipherData) - aesGCM.Overhead() {
		return fmt.Errorf("Plaindata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(cipherData) + aesGCM.Overhead()), len(plainData))
	}
	_, err = aesGCM.Open(plainData[:0], nonce, cipherData, nil)
	return err
}

func GenTestAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGCM, nil
}



func (A AES256GCM) EncryptReturn(key, nonce, plainData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// only for the first and last one
	if len(nonce) != aesGCM.NonceSize() {
		return nil, fmt.Errorf("Invalid Nonce size, should be: %d , got: %d", aesGCM.NonceSize(), len(nonce))
	}

	
	// cipherdata is writen to cipherData passed as first argument
	cipherData := aesGCM.Seal(nil, nonce, plainData, nil)
	//_ = aesGCM.Seal(nil, nonce, plainData, nil)
	return cipherData, nil 
}

func (A AES256GCM) DecryptReturn(key, nonce, cipherData []byte) ([]byte, error) {
	//decrypted := []byte{} 
	if len(key) != 32 {
		return nil, fmt.Errorf("Key length is not 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesGCM.NonceSize() {
		return nil, fmt.Errorf("Invalid Nonce size, should be: %d , got: %d", aesGCM.NonceSize(), len(nonce))
	}
	//if len(plainData) < len(cipherData) + aesGCM.Overhead() {
	plainData, err := aesGCM.Open(nil, nonce, cipherData, nil)
	return plainData, err
}

