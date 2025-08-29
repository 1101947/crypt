package kdf

import (
	"YSNP2/argon2id"
)

type Argon2idParams struct {
	P argon2id.Params
}
type Kdf interface {
	Hash(key, salt []byte) ([]byte, error)
}

func (params Argon2idParams) Hash(key, salt []byte) ([]byte, error) {
	p := params.P
	hashed, err := argon2id.Hash(key, salt, p)
	if err != nil {
		return nil, err
	}
	return hashed, nil
}
