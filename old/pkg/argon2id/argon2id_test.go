package argon2id 

import (
	"testing"
)

// TODO TestNewParams

func TestNewDefaultParams(t *testing.T) {
	p := NewDefaultParams()
	if uint32(7168) > p.memory {
		t.Errorf("Memory parametr value is invalid. Should be more 7168")
	}
	if p.memory > uint32(47104) {
		t.Errorf("Memory parametr value is invalid. Should be less 47104")
	}
	if uint32(1) > p.iterations {
		t.Errorf("Iterations parametr value is invalid. Should be more than 1")
	}
	if p.iterations >= uint32(5) {
		t.Errorf("Iterations parametr value is invalid. Should be less than 5")
	}
	if p.parallelism != uint8(1) {
		t.Errorf("Parallelism parametr value is invalid. Should be 1.")
	}
	//TODO maybe test other params
}

func TestNewSalt(t *testing.T) {
	size := uint32(16)
	_, err := NewSalt(size)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestHash(t *testing.T) {
	params := NewDefaultParams()
	password := []byte("password") 
	salt, err := random(params.saltLength)
	if err != nil {
		t.Errorf("%v", err)
	}
	_, err = Hash(password, salt, params)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestCompare(t *testing.T) {
	params := NewDefaultParams()
	password := []byte("password") 
	salt, err := random(params.saltLength)
	if err != nil {
		t.Errorf("%v", err)
	}
	hashed, err := Hash(password, salt, params)
	if err != nil {
		t.Errorf("%v", err)
	}
	shouldBeEqual, err := Compare(password, hashed, salt, params)
	if err != nil {
		t.Errorf("%v", err)
	}
	if shouldBeEqual != true {
		t.Errorf("Hash and password comparison value should be true, but is false")
	}
	otherPassword := []byte("another password") 
	shouldNotBeEqual, err := Compare(otherPassword, hashed, salt, params)
	if err != nil {
		t.Errorf("%v", err)
	}
	if shouldNotBeEqual != false {
		t.Errorf("Hash and password comparison value should be false, but is true")
	}
	otherSalt, err := random(params.saltLength)
	if err != nil {
		t.Errorf("%v", err)
	}
	shouldNotBeEqual, err = Compare(password, hashed, otherSalt, params)
	if err != nil {
		t.Errorf("%v", err)
	}
	if shouldNotBeEqual != false {
		t.Errorf("Hash and password comparison value should be false, but is true")
	}

}
