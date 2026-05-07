package secret

import (
	"crypt/argon2id"
)

func GetKey(params argon2id.Params) ([]byte, error) {
	s, err := term.ReadPassword(1)
	if err != nil {
		return nil, err
	}
	key, err := params.Hash([]byte(s))
	if err != nil {
		return nil, err
	} 
	return key, nil
}
