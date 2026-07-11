package chacha20poly1305

import (
	//"io"
	"fmt"
	//"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
)


type ChaCha20Poly1305 bool

func GetChaCha20Poly1305() ChaCha20Poly1305 {
	return ChaCha20Poly1305(true)
}

func (C ChaCha20Poly1305) Encrypt(key, nonce, plainData, cipherData []byte) error {
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


func (C ChaCha20Poly1305) Decrypt(key, nonce, cipherData, plainData []byte) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return fmt.Errorf("Invalid nonce size, must be %d bytes, but got: %d", chacha20poly1305.NonceSizeX, len(nonce))
	}
//	if len(plainData) < len(cipherData) - aead.Overhead() {
//		return fmt.Errorf("Plaindata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(cipherData) + aead.Overhead()), len(plainData))
//	}
	_, err = aead.Open(plainData[:0], nonce, cipherData, nil)
	return err 
}




func (C ChaCha20Poly1305) EncryptReturn(key, nonce, plainData []byte) ([]byte, error) {
// Consider: should i add check for key length or chacha20poly1305.NewX() already does that ? 
//	if len(key) != chacha20poly1305.KeySize {
//		return fmt.Errorf("Key length is not %d", chacha20poly1305.KeySize)
//	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("Invalid nonce size, must be %d bytes, but got: %d", chacha20poly1305.NonceSizeX, len(nonce))
	}
//	if len(cipherData) < len(plainData) + aead.Overhead() {
//		return nil, fmt.Errorf("Cipherdata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(plainData) + aead.Overhead()), len(cipherData))
//	}
	cipherData := aead.Seal(nil, nonce, plainData, nil)
	return cipherData, nil 
}


func (C ChaCha20Poly1305) DecryptReturn(key, nonce, cipherData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("Invalid nonce size, must be %d bytes, but got: %d", chacha20poly1305.NonceSizeX, len(nonce))
	}
	//fmt.Println(len(plainData), len(cipherData), aead.Overhead())
//	if len(plainData) < len(cipherData) - aead.Overhead() {
//		return fmt.Errorf("Plaindata buffer is too short. Must be at least %d bytes , but got: %d bytes", (len(cipherData) + aead.Overhead()), len(plainData))
//	}
	plainData, err := aead.Open(nil, nonce, cipherData, nil)
	return plainData, err 
}
