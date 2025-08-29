package hash_and_crypt

import (
	"YSNP2/kdf"
	"YSNP2/symm_crypt"
)

type Header struct {
	kdf.Kdf
	symm_crypt.Crypter
	Salt []byte
}

func NewHeader(k kdf.Kdf, crypter symm_crypt.Crypter, s []byte) Header {
	neW := Header{
		Kdf:  k,
		Crypter: crypter,
		Salt: s, 
	}
	return neW
}

type CryptoInput struct {
	ReturnCryptoKey bool
	InputKey []byte
	Data []byte
	Header 
}

func NewCryptoInput(i, d []byte, r bool, h Header) CryptoInput {
	neW := CryptoInput{
		ReturnCryptoKey: r,
		InputKey: i,
		Data: d,
		Header: h,
	}
	return neW
}

type CryptoOutput struct {
	CryptoKey []byte
	Crypted []byte
}

func Encrypt(c CryptoInput) (CryptoOutput, error) {
	out := CryptoOutput{}
	cryptoKey, err := (c.Kdf).Hash(c.InputKey, c.Salt)
	out.CryptoKey = cryptoKey
	if err != nil {
		return out, err
	}
	out.Crypted, err = c.Crypter.Encrypt(c.Data, out.CryptoKey)
	if err != nil {
		return out, err
	}
	if c.ReturnCryptoKey == true {
		out.CryptoKey = nil
	}
	return out, nil
}

func Decrypt(c CryptoInput) (CryptoOutput, error) {
	out := CryptoOutput{}
	cryptoKey, err := (c.Kdf).Hash(c.InputKey, c.Salt)
	out.CryptoKey = cryptoKey
	if err != nil {
		return out, err
	}
	out.Crypted, err = c.Crypter.Decrypt(c.Data, out.CryptoKey)
	if err != nil {
		return out, err
	}
	if c.ReturnCryptoKey == true {
		out.CryptoKey = nil
	}
	return out, nil
}

