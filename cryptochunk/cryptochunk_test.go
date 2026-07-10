package cryptochunk

import (
	"testing"
	"crypt/aes256gcm"
)

func TestCryptoChunk(t *testing.T) {
	plainData1 := "kkkkkkkkkkkkkkkkkkkklalalalllllllllllllllllllllllllllllllllllll"
	var plainData2 string
	aesGCMOverhead := 16
	plainData2buf := make([]byte, len(plainData1)+aesGCMOverhead)  
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
