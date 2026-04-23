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
