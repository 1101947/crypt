package chacha20poly1305

import (
	"io"
	"fmt"
	"crypto/rand"


	"golang.org/x/crypto/chacha20poly1305"
)


func Encrypt(key []byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	encrypted = aead.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

func EncryptPtr(key, nonce, plainData, cipherData []byte) error {
// Consider: should i add check for key length or chacha20poly1305.NewX() already does that ? 
//	if len(key) != chacha20poly1305.KeySize {
//		return fmt.Errorf("Key length is not %d", chacha20poly1305.KeySize)
//	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return fmt.Errorf("Invalid nonce size, must be %d bytes, but got: %d", chacha20poly1305.NonceSizeX, len(nonce))
	}
	if len(cipherData) < len(plainData) + aead.Overhead() {
		return fmt.Errorf("Cipherdata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(plainData) + aead.Overhead()), len(cipherData))
	}
	_ = aead.Seal(cipherData[:0], nonce, plainData, nil)
	return nil
}


func Decrypt(key, encrypted []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < aead.NonceSize() {
		return nil, fmt.Errorf("encrypted data is too short")
	}
	nonce, encryptedData := encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():]
	decrypted, err := aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}


func DecryptPtr(key, nonce, cipherData, plainData []byte) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return fmt.Errorf("Invalid nonce size, must be %d bytes, but got: %d", chacha20poly1305.NonceSizeX, len(nonce))
	}
	if len(plainData) < len(cipherData) + aead.Overhead() {
		return fmt.Errorf("Plaindata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(cipherData) + aead.Overhead()), len(plainData))
	}
	_, err = aead.Open(plainData, nonce, cipherData, nil)
	return err 
}
