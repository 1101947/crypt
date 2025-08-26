package internal

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)



type params struct {
	saltLength uint32
	iterations uint32
	memory uint32
	parallelism uint8
	keyLength uint32
}

func NewParams(s uint32, i uint32, m uint32, p uint8, k uint32) params {
	params := params{}
	params.saltLength = s
	params.iterations = i
	params.memory = m
	params.parallelism = p
	params.keyLength = k
	return params
}

func NewDefaultParams() params {
	p := params{
		saltLength: 16,
		iterations: 1,
		memory: 46 * 1024,
		parallelism: 1,
		keyLength: 32,
	}
	return p
}

func Hash(password, salt []byte, p params) ([]byte, error) {
	// TODO: create my own random function in rundom module
	hash := []byte{}
	hash = argon2.IDKey(password, salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash, nil
}

func Compare(password, hash, salt []byte, p params) (bool, error) {
	newHash, err := Hash(password, salt, p)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(hash, newHash) == 1 {
		return true, nil
	} 
	return false, nil
} 

func random(u uint32) ([]byte, error) {
	b := make([]byte, u)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func NewSalt(size uint32) ([]byte, error) {
	salt, err := random(size)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
