package internal 

import (
	"testing"
	"crypto/rand"
)

func TestEncrypt(t *testing.T) {
	expect := []byte("test")
	dontExpect := []byte("best")
	key := make([]byte, 32) 
	if _, err := rand.Read(key); err != nil {
		t.Errorf("Got error: %v", err)
	}
	key32 := [32]byte{}
	copy(key32[:], key)
	encrypted, err := Encrypt(key32, expect)
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	have, err := decrypt(key32, encrypted)
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	for i, _ := range expect {
		if have[i] != expect[i] {
			t.Errorf("Encryption or decryption failed")
		}
	}
	counter := 0
	for i, v := range dontExpect {
		if have[i] != v {
			counter++
		}
	} 
	if counter == 0 {
		t.Errorf("Test must fail, but it didnt")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for b.Loop() {
		// Maybe shouldnt use for loop
		key := [32]byte{}
		for x:=0; x<32; x++ {
			key[x] = byte(x)
		}
		data := []byte("test")
		Encrypt(key, data)
	}
}

// TODO: test decrypt, without testing encrypt
