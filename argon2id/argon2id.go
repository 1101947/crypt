package argon2id 

import (
	"fmt"

	//"crypto/rand"
	"golang.org/x/crypto/argon2"
)

type Params struct {
	Salt []byte
	Version string
	SaltLength uint32
	Iterations uint32
	Memory uint32
	Parallelism uint8
	KeyLength uint32
}

func (P Params) Hash(key []byte) ([]byte, error) {
//	if len(key) != int(P.KeyLength) {
//		return nil, fmt.Errorf("Provided key length: %d differs from the one stated in params: %d ", len(key), P.KeyLength)
//	}
	if len(P.Salt) != int(P.SaltLength) {
		return nil, fmt.Errorf("Provided salt length: %d differs from the one stated in params: %d ", len(P.Salt), P.SaltLength)
	}
	hashKey := argon2.IDKey(key, P.Salt, P.Iterations, P.Memory, P.Parallelism, P.KeyLength)
	return hashKey, nil
}
