package cryptochunk

import (
	"testing"
	"fmt"
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
	//fmt.Printf("chnk1: %+v", chnk1)
	err := chnk1.Encrypt()
	if err != nil {
		t.Errorf("%v", err)
	}
	//fmt.Printf("chnk1: %+v", chnk1)
	chnk1.In = chnk1.Out
	chnk1.Out = plainData2buf 
	//fmt.Printf("chnk1: %+v", chnk1)
	err = chnk1.Decrypt()
	if err != nil {
		t.Errorf("%v", err)
	}
	//fmt.Printf("\nResult: %+v , %+v\n", chnk1.Out, plainData2)
	plainData2 = string(plainData2buf)
	if plainData1 != plainData2 {
		t.Errorf("Expected plainData1: \"%s\" to be equal to plainData2: \"%s\", but they are not.", plainData1, plainData2)
	}
}



func TestCryptoChunkChaCha20Poly1305(t *testing.T) {
	plainData1 := "llllllllllllllllllllll"
	var plainData2 string
	chachaOverhead := 32 
	//plainData2buf := make([]byte, len(plainData1))  
	cryptData := make([]byte, len(plainData1)+chachaOverhead)

	plainData2buf := make([]byte, len(plainData1))  
	secretKey := []byte("11111111111111111111111111111111")
	//nonceSrc := []byte("123456789012")
	nonceSrc := make([]byte, 24)
	i, err := rand.Read(nonceSrc)
	if err != nil {
		t.Errorf("ERROR %v : %d", err, i)
	}

	chnk1 := CryptChunk{
		In: []byte(plainData1),
		Out: cryptData, 
		Key: secretKey,
		NonceSource: nonceSrc,
		ChunkPosition: 1,
		Crypter: chacha20poly1305.GetChaCha20Poly1305(),
	}
	//fmt.Printf("chnk1: %+v", chnk1)
	err = chnk1.Encrypt()
	if err != nil {
		t.Errorf("%v", err)
	}
	fmt.Printf("chnk1: %+v\n", chnk1)
	chnk1.In = chnk1.Out
	chnk1.Out = plainData2buf 
	fmt.Printf("chnk1: %+v\n", chnk1)
	err = chnk1.Decrypt()
	fmt.Printf("chnk1: %+v\n", chnk1)
	if err != nil {
		t.Errorf("%v", err)
	}
	//fmt.Printf("\nResult: %+v , %+v\n", chnk1.Out, plainData2)
	plainData2 = string(plainData2buf)
	if string(plainData1) != plainData2 {
		t.Errorf("Expected plainData1: \"%s\" to be equal to plainData2: \"%s\", but they are not.", string(plainData1), plainData2)
	}
}
