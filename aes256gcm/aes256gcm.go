package aes256gcm 

import (
	//"io"
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	//"crypto/rand"
)

func Encrypt(key, nonce, data []byte) ([]byte, error) {
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
	// nonce := make([]byte, aesGCM.NonceSize(), aesGCM.NonceSize()+len(data)+aesGCM.Overhead())
//	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
//		return sealed, err
//	}

	if len(nonce) != aesGCM.NonceSize() {
		return nil, fmt.Errorf("Passed nonce length differs from expected nonce size: %d", aesGCM.NonceSize())
	}
//	if cap(nonce) != aesGCM.NonceSize()+len(data)+aesGCM.Overhead() {
//		return nil, fmt.Errorf("Passed nonce capacity differs from expected")
//	}
	sealed = aesGCM.Seal(nonce, nonce, data, nil)
	return sealed, nil
}

func EncryptPtr(key, nonce, plainData, cipherData []byte) error {
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
	if len(cipherData) < len(plainData) + aesGCM.Overhead() {
		return fmt.Errorf("Cipherdata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(plainData) + aesGCM.Overhead()), len(cipherData))
	}
	// cipherdata is writen to cipherData passed as first argument
	_ = aesGCM.Seal(cipherData[:0], nonce, plainData, nil)
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
	_, err = aesGCM.Open(plainData, nonce, cipherData, nil)
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
