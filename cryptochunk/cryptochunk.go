package cryptochunk

import (
	"fmt"
	"encoding/binary"
)

type Crypter interface {
	Encrypt(key, nonce, plainData, cipherData []byte) error
	Decrypt(key, nonce, plainData, cipherData []byte) error
	GetOverhead(key []byte) (uint64, error)
	GetNonceSize(key []byte) (uint64, error)
}

type CryptChunk struct {
	In, Out, Key, NonceSource []byte
	// TODO: consider changing type of ChunkPosition to int
	ChunkPosition uint64
	Crypter Crypter
}

func (C CryptChunk) Encrypt() error {
	nonce := GenerateNonce(C.NonceSource, C.ChunkPosition)
	err := C.Crypter.Encrypt(C.Key, nonce, C.In, C.Out)
	if err != nil {
		return fmt.Errorf("Encrypting data at pointer, got %w", err)
	}
	return nil
}

func (C CryptChunk) Decrypt() error {
	nonce := GenerateNonce(C.NonceSource, C.ChunkPosition)
	err := C.Crypter.Decrypt(C.Key, nonce, C.In, C.Out)
	if err != nil {
		return fmt.Errorf("Decrypting data at pointer, got: %w", err)
	}
	return nil
}

//// TODO: make sure this works correctly
func GenerateNonce(source []byte, chunkNumber uint64) []byte {
	buf := make([]byte, len(source))
	binary.LittleEndian.PutUint64(buf, chunkNumber)
	newnonce := make([]byte, len(source))
	for i:=0; i<12; i++ {
		newnonce[i] = buf[i] ^ source[i]
		
	}
	return newnonce
}

