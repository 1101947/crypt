package chacha20poly1305 

import (
	"testing"
	"crypto/rand"
)

func TestCrypt(t *testing.T) {
	cha := GetChaCha20Poly1305()
	key := make([]byte, 32)
	i, err := rand.Read(key)
	if i != 32 {
		t.Errorf("i must be equal to 32, but it is %d", i)
	}
	if err != nil {
		t.Errorf("ERROR: %v : %d", err, i)
	}
	nonce := make([]byte, 24)
	i, err = rand.Read(nonce)
	if err != nil {
		t.Errorf("ERROR %v : %d", err, i)
	}

	plainData := []byte("la la la just data it is")
	cipherData := make([]byte, len(plainData)+16) 

	err = cha.Encrypt(key, nonce, plainData, cipherData)
	if err != nil {
		t.Errorf("ERROR %v", err)
	}
	resultPlainData := make([]byte, len(plainData)) 
	err = cha.Decrypt(key, nonce, cipherData, resultPlainData)
	if err != nil {
		t.Errorf("ERROR: %v", err)
	}
	if string(plainData) != string(resultPlainData) {
		t.Errorf("Expected plainData \"%s\" to be equal to resultPlainData \"%s\"", plainData, resultPlainData)
	}
}


func TestCryptReturn(t *testing.T) {
	cha := GetChaCha20Poly1305()
	key := make([]byte, 32)
	i, err := rand.Read(key)
	if i != 32 {
		t.Errorf("i must be equal to 32, but it is %d", i)
	}
	if err != nil {
		t.Errorf("ERROR: %v : %d", err, i)
	}
	nonce := make([]byte, 24)
	i, err = rand.Read(nonce)
	if err != nil {
		t.Errorf("ERROR %v : %d", err, i)
	}

	plainData := []byte("la la la just data it is")
	//cipherData := make([]byte, len(plainData)+16) 

	cipherData, err := cha.EncryptReturn(key, nonce, plainData)
	if err != nil {
		t.Errorf("ERROR %v", err)
	}
	resultPlainData, err := cha.DecryptReturn(key, nonce, cipherData)
	if err != nil {
		t.Errorf("ERROR: %v", err)
	}
	if string(plainData) != string(resultPlainData) {
		t.Errorf("Expected plainData \"%s\" to be equal to resultPlainData \"%s\"", plainData, resultPlainData)
	}
}
