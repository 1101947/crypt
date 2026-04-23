package encrypted 

import (
	"fmt"

	"crypt/crypt"
	"crypt/argon2id"
)

type Encrypted struct {
	Header Header
	Body []byte
}

type Header struct {
	Version string
	SymmCryptFunc string
	Kdf argon2id.Params
}

func (H Header) Encrypt(key, data []byte) ([]byte, error) {
	derivedKey, err := (H.Kdf).Hash(key)
	if err != nil {
		return nil, fmt.Errorf("Deriving key, got error: %w", err)
	}
	encrypted, err := crypt.Encrypt(H.SymmCryptFunc, derivedKey, data)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (H Header) Decrypt(key, encrypted []byte) ([]byte, error) {
	derivedKey, err := (H.Kdf).Hash(key)
	if err != nil {
		return nil, fmt.Errorf("Deriving key, got error: %w", err)
	}
	decrypted, err := crypt.Decrypt(H.SymmCryptFunc, derivedKey, encrypted)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}





