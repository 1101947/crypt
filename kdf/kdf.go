package kdf

import (
	"fmt"

	"crypt/argon2id"
	"crypt/rand"
)

type Kdf interface {
	Init() Kdf
	Hash(key, salt []byte) ([]byte, error)
}

type Argon2idParams struct {
	P argon2id.Params
	Salt 
}

type Salt struct {
	Salt []byte
	SaltSize uint32
}

func (params Argon2idParams) Init() Kdf {
	p := argon2id.NewDefaultParams() 
	salt := rand.Salt(p.SaltLength)
	params.P = p
	params.Salt = salt
	parmas.SaltSize = p.SaltLength
}

func (params Argon2idParams) Hash(key []byte) ([]byte, error) {
	p := params.P
	hashed, err := argon2id.Hash(key, p.Salt, p)
	if err != nil {
		return nil, err
	}
	return hashed, nil
}

type InvalidKDF struct {}

func (i InvalidKDF) Hash(key, salt []byte) ([]byte, error) {
	return nil, fmt.Errorf("Ivalid KDF")
}

func Parse(s []string) (Kdf, error) {
	counter := 0
	kdfString := ""
	for _, arg := range s {
		if arg[:5] == "--kdf=" {
			counter++
			kdfString = arg[5:]
		}
	}
	argon2idParams := Argon2idParams{}
	argon2idParams.P = argon2id.NewDefaultParams()
	if counter == 0 {
		return argon2idParams, nil // Default 
	}
	if counter == 1 {
		if kdfString == "argon2id" {
			return argon2idParams, nil
		}
	}
	return InvalidKDF{}, fmt.Errorf("More than one kdf parameter")
}
