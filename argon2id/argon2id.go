package argon2id 

import (
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)



type Params struct {
	SaltLength uint32
	Iterations uint32
	Memory uint32
	Parallelism uint8
	KeyLength uint32
}

func (p Params) GetSaltLength() uint32 {
	return p.SaltLength
}
//
//func NewParams(s uint32, i uint32, m uint32, p uint8, k uint32) params {
//	params := params{}
//	params.saltLength = s
//	params.iterations = i
//	params.memory = m
//	params.parallelism = p
//	params.keyLength = k
//	return params
//}

func NewDefaultParams() Params {
	p := Params{
		SaltLength: 16,
		Iterations: 1,
		Memory: 46 * 1024,
		Parallelism: 1,
		KeyLength: 32,
	}
	return p
}

func Hash(password, salt []byte, p Params) ([]byte, error) {
	hash := []byte{}
	hash = argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return hash, nil
}

func Compare(password, hash, salt []byte, p Params) (bool, error) {
	newHash, err := Hash(password, salt, p)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(hash, newHash) == 1 {
		return true, nil
	} 
	return false, nil
} 

