package cli

import (
	"fmt"
	"golang.org/x/term"
	"crypt/argon2id"
)

type cliKeyGetter string

func (c cliKeyGetter) GetKey(P argon2id.Params) ([]byte, error) {
	fmt.Println("Provide password: ")
	s, err := term.ReadPassword(1)
	if err != nil {
		return nil, err
	}
	userKey := []byte(s)
	key, err := P.Hash(userKey)
	if err != nil {
		return nil, fmt.Errorf("Hashing, got: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("Invalid key length: %d", len(key))
	}
	return key, nil
}
