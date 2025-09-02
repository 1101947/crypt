package encrypt 

import (
	"strings"
	"os"
	"fmt"

	"crypt/crypt/symm"
	"crypt/cli/get_password"
	"crypt/kdf"
	"crypt/symm_crypt"
	"crypt/rand"
)

func ReadCli() ((symm.CryptoInput), error) {
	args := os.Args
	cryptoIn := symm.CryptoInput{}
	cryptoIn.ReturnCryptoKey = false
	numberOfFlags := 0
	// TODO : provide user with the ability to choose file as data source
	data := []byte(strings.Join(args[numberOfFlags+1:], " "))
	cryptoIn.Data = data 
	// TODO : provide user with other types of key (key-file)
	fmt.Println("Enter password:")
	password, err := get_password.GetPassword() 
	if err != nil {
		return cryptoIn, err
	}
	cryptoIn.InputKey = password
	kdF, err := kdf.Parse(args[:numberOfFlags+1])
	if err != nil {
		return cryptoIn, err
	}
	crypter, err := symm_crypt.Parse(args[:numberOfFlags+1])
	if err != nil {
		return cryptoIn, err
	}
	salt, err := rand.Salt(kdF.SaltSize)
	if err != nil {
		return cryptoIn, err
	}
	header := symm.NewHeader(kdF, crypter, kdF.Salt)
	cryptoIn.Header = header 
	return cryptoIn, nil
}

func returnResult(c symm.CryptoOutput) string {
	return fmt.Sprintf("%v", c.Crypted)
}

func ProcessEncryption() (string, error) {
	cryptIn, err := ReadCli()
	if err != nil {
		return "", err
	}
	cryptOut, err := symm.Encrypt(cryptIn)
	if err != nil {
		return "", err
	}
	str := returnResult(cryptOut)
	return str, nil 

	
}
