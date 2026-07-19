package aes256gcm 

import (
	"fmt"
	"crypto/aes"
	"crypto/cipher"
)

// key must be 32bytes
// nonce at least 12bytes
type AES256GCM bool

func GetAES256GCM() AES256GCM {
	return AES256GCM(true)
}

func (A AES256GCM) GetOverhead(key []byte) (uint16, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}
	overhead := aesGCM.Overhead()
	if overhead < 0 {
		return 0, fmt.Errorf("Invalid overhead value: negative: %d", overhead)
	}
	return uint16(overhead), nil
}

func (A AES256GCM) GetNonceSize(key []byte) (uint16, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}
	nonceSize := aesGCM.NonceSize()
	if nonceSize < 0 {
		return 0, fmt.Errorf("Invalid nonceSize value: negative: %d", nonceSize)
	}
	return uint16(nonceSize), nil
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
	// cipherdata is writen to cipherData passed as first argument
	_ = aesGCM.Seal(cipherData[:0], nonce, plainData, nil)
	return nil
}

func (A AES256GCM) Decrypt(key, nonce, cipherData, plainData []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
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

