package argon2id 

import (
	"fmt"

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

type validParams struct {
	saltLength uint32
	iterations uint32
	memory uint32
	parallelism uint8
	keyLength uint32
}

func (p Params) Validate() (validParams, error) {
	params := validParams{}
	if p.SaltLength == 0 {
		return params, fmt.Errorf("Salt length size must be greater than zero")
	}
	if p.Iterations == 0 {
		return params, fmt.Errorf("The minimum number of iterations must be greater than zero")
	}
	if p.Memory == 0 {
		return params, fmt.Errorf("Memory size must be greater than zero")
	}
	if p.Parallelism == 0 {
		return params, fmt.Errorf("Degree of parallelism must be greater than zero")
	}
	if p.KeyLength == 0 {
		return params, fmt.Errorf("Key length must be greater than zero")
	}
	params.saltLength = p.SaltLength
	params.iterations = p.Iterations
	params.memory = p.Memory
	params.parallelism = p.Parallelism
	params.keyLength = p.KeyLength
	return params, nil
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
		Iterations: 2,
		Memory: 19 * 1024,
		Parallelism: 1,
		KeyLength: 32,
	}
	return p
}

func Hash(password, salt []byte, p validParams) ([]byte, error) {
	hash := []byte{}
	hash = argon2.IDKey(password, salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash, nil
}

func Compare(password, hash, salt []byte, p validParams) (bool, error) {
	newHash, err := Hash(password, salt, p)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(hash, newHash) == 1 {
		return true, nil
	} 
	return false, nil
} 

type PHCFormat struct {
	Id string
	Version string
	PArams
	Salt []byte
	Hash []byte
}

func (p phcFormat) PHCToString string {
}
