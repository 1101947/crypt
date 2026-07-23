package cryptochunk

import (
	"testing"
	"crypto/rand"
	"crypt/aes256gcm"
	"crypt/chacha20poly1305"
)

func TestCryptoChunkAes256Gcm(t *testing.T) {
	plainData1 := "llllllllllllllllllllll"
	var plainData2 string
	aesGCMOverhead := 16
	plainData2buf := make([]byte, len(plainData1))  
	cryptData := make([]byte, len(plainData1)+aesGCMOverhead)  
	secretKey := []byte("11111111111111111111111111111111")
	nonceSrc := []byte("123456789012")
	chnk1 := CryptChunk{
		In: []byte(plainData1),
		Out: cryptData, 
		Key: secretKey,
		NonceSource: nonceSrc,
		ChunkPosition: 1,
		Crypter: aes256gcm.GetAES256GCM(),  
	}
	err := chnk1.Encrypt()
	if err != nil {
		t.Errorf("%v", err)
	}
	chnk1.In = chnk1.Out
	chnk1.Out = plainData2buf 
	err = chnk1.Decrypt()
	if err != nil {
		t.Errorf("%v", err)
	}
	plainData2 = string(plainData2buf)
	if plainData1 != plainData2 {
		t.Errorf("Expected plainData1: \"%s\" to be equal to plainData2: \"%s\", but they are not.", plainData1, plainData2)
	}
}


func TestCryptoChunkChaCha20Poly1305(t *testing.T) {
	// Dont use magick number, replace with argon2id.ArgonHeader.KeyLength
	key := make([]byte, 32)
	i, err := rand.Read(key)
	if err != nil {
		t.Errorf("ERROR: %v : %d", err, i)
	}
	if i != 32 {
		t.Errorf("i must be equal to 32, but it is %d", i)
	}
	nonce := make([]byte, 24)
	i, err = rand.Read(nonce)
	if err != nil {
		t.Errorf("ERROR %v : %d", err, i)
	}

	plainData := []byte("la la la just data it is")
	cipherData := make([]byte, len(plainData)+16)

	chnk1 := CryptChunk{
		In: plainData,
		Out: cipherData,
		Key: key,
		NonceSource: nonce,
		ChunkPosition: 1,
		Crypter: chacha20poly1305.GetChaCha20Poly1305(),
	}
	err = chnk1.Encrypt()
	if err != nil {
		t.Errorf("ERROR %v", err)
	}
	resultPlainData := make([]byte, len(plainData))
	chnk1.In = chnk1.Out
	chnk1.Out = resultPlainData
	err = chnk1.Decrypt()
	if err != nil {
		t.Errorf("ERROR: %v", err)
	}
	if string(plainData) != string(resultPlainData) {
		t.Errorf("Expected plainData \"%s\" to be equal to resultPlainData \"%s\"", plainData, resultPlainData)
	}
}

