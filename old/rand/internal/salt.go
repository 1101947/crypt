package internal 

import ()

func NewSalt(size uint32) ([]byte, error) {
	salt, err := RandomBytes(size)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
