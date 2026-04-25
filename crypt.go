package main

import (
	"os"
	"fmt"
	"bufio"
	"strings"
	"encoding/json"
	"crypto/rand"
	"crypt/encrypted"
	"crypt/argon2id"

	"golang.org/x/term"
	//"github.com/1101947/cliargumentrouter/cmdrouter"
)
//
//type EncrtyptHandler struct {
//	Interactive string
//}

func EncryptCMD(posargs []string) error {
	fmt.Println("Encrypt: ")
	fmt.Printf("Enter source path: ")
	reader := bufio.NewReader(os.Stdin)
	sp, _ := reader.ReadString('\n')
	sp = strings.TrimSpace(sp)
	fmt.Printf("Enter destination path: ")
	dp, _ := reader.ReadString('\n')
	dp = strings.TrimSpace(dp)
	c := cryptData{
		sourcePath: sp,
		destPath: dp,
		symmCryptFuncToUse: "aes256gcm", 
		slen: 16, 
		iter: 1, 
		mem: 64*1024,
		klen: 32, 
		paral: 4, 
	}
	err := c.Encrypt()
	//err := c.Decrypt()
	return err
}

func DecryptCMD(posargs []string) error {
	fmt.Println("Encrypt: ")
	fmt.Printf("Enter source path: ")
	reader := bufio.NewReader(os.Stdin)
	sp, _ := reader.ReadString('\n')
	sp = strings.TrimSpace(sp)
	fmt.Printf("Enter destination path: ")
	dp, _ := reader.ReadString('\n')
	dp = strings.TrimSpace(dp)
	c := cryptData{
		sourcePath: sp,
		destPath: dp,
		symmCryptFuncToUse: "aes256gcm", 
		slen: 16, 
		iter: 1, 
		mem: 64*1024,
		klen: 32, 
		paral: 4, 
	}
	//err := c.Encrypt()
	err := c.Decrypt()
	return err
}


type cryptData struct {
	sourcePath string
	destPath string
	symmCryptFuncToUse string
	slen uint32
	iter uint32
	mem uint32
	klen uint32
	paral uint8
}

func (c cryptData) Encrypt() error {
	data, err := os.ReadFile(c.sourcePath)
	if err != nil {
		return fmt.Errorf("Trying to read file, got: %w", err)
	}
	//var model encrypted.Encrypted
	//err = json.Unmarshal(jsonData, &model)
	//if err != nil {
	//	return fmt.Errorf("Trying to unmarshall json, got: %w", err)
	//}
	salt, err := GenSalt(int(c.slen))
	if err != nil {
		return err
	}
	header := encrypted.Header{
		Version: "",
		SymmCryptFunc: c.symmCryptFuncToUse,
		Kdf: argon2id.Params{
			Salt: salt,
			Version: "",
			SaltLength: c.slen,
			Iterations: c.iter,
			Memory: c.mem,
			Parallelism: c.paral,
			KeyLength: c.klen,
		},
	}
	key, err  := GetKey()
	if err != nil {
		return fmt.Errorf("Geting key from user, got: %w", err)
	}
	body, err := header.Encrypt(key, data)
	if err != nil {
		return err
	}
	model := encrypted.Encrypted{
		Header: header,
		Body: body,
	}
	encrptd, err := json.Marshal(&model)
	if err != nil {
		return err
	}
	os.WriteFile(c.destPath, encrptd, 0644)
	return nil
}

func GenSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func GetKey() ([]byte, error) {
	fmt.Printf("Provide password: ")
	s, err := term.ReadPassword(1)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func (c cryptData) Decrypt() error {
	jsonData, err := os.ReadFile(c.sourcePath)
	if err != nil {
		return fmt.Errorf("Trying to read file, got: %w", err)
	}
	var model encrypted.Encrypted
	err = json.Unmarshal(jsonData, &model)
	if err != nil {
		return fmt.Errorf("Trying to unmarshall json, got: %w", err)
	}
	key, err  := GetKey()
	if err != nil {
		return fmt.Errorf("Geting key from user, got: %w", err)
	}
	decrypted, err := (model.Header).Decrypt(key, model.Body)
	if err != nil {
		return fmt.Errorf("Encrypting got: %w", err)
	}
	os.WriteFile(c.destPath, decrypted, 0644)
	return nil
}
