package main

import (
	//"os"
	"fmt"
	"strings"
//	"encoding/json"
//	"crypto/rand"
//	"crypt/encrypted"
//	"crypt/argon2id"
//
//	"golang.org/x/term"
	"github.com/1101947/cliargumentrouter/cmdrouter"

)

//type cryptData struct {
//	sourcePath string
//	destPath string
//	symmCryptFuncToUse string
//	slen uint32
//	iter uint32 
//	mem uint32
//	klen uint32 
//	paral uint8 
//}
//
//func (c cryptData) Encrypt() error {
//	data, err := os.ReadFile(c.sourcePath)
//	if err != nil {
//		return fmt.Errorf("Trying to read file, got: %w", err)
//	}
//	//var model encrypted.Encrypted 
//	//err = json.Unmarshal(jsonData, &model)
//	//if err != nil {
//	//	return fmt.Errorf("Trying to unmarshall json, got: %w", err)
//	//}
//	salt, err := GenSalt(int(c.slen))
//	if err != nil {
//		return err 
//	}
//	header := encrypted.Header{
//		Version: "",
//		SymmCryptFunc: c.symmCryptFuncToUse,
//		Kdf: argon2id.Params{
//			Salt: salt,
//			Version: "",
//			SaltLength: c.slen,
//			Iterations: c.iter,
//			Memory: c.mem,
//			Parallelism: c.paral,
//			KeyLength: c.klen,
//		},
//	}
//	key, err  := GetKey()
//	if err != nil {
//		return fmt.Errorf("Geting key from user, got: %w", err)
//	}
//	body, err := header.Encrypt(key, data)
//	if err != nil {
//		return err
//	}
//	model := encrypted.Encrypted{
//		Header: header,
//		Body: body,
//	}
//	encrptd, err := json.Marshal(&model)
//	if err != nil {
//		return err
//	}
//	os.WriteFile(c.destPath, encrptd, 0644)
//	return nil
//}
//
//func GenSalt(length int) ([]byte, error) {
//	salt := make([]byte, length)
//	_, err := rand.Read(salt)
//	if err != nil {
//		return nil, err 
//	}
//	return salt, nil
//}
//
//func GetKey() ([]byte, error) {
//	fmt.Printf("Provide password: ")
//	s, err := term.ReadPassword(1)
//	if err != nil {
//		return nil, err 
//	}
//	return []byte(s), nil
//}
//
//func (c cryptData) Decrypt() error {
//	jsonData, err := os.ReadFile(c.sourcePath)
//	if err != nil {
//		return fmt.Errorf("Trying to read file, got: %w", err)
//	}
//	var model encrypted.Encrypted 
//	err = json.Unmarshal(jsonData, &model)
//	if err != nil {
//		return fmt.Errorf("Trying to unmarshall json, got: %w", err)
//	}
//	key, err  := GetKey()
//	if err != nil {
//		return fmt.Errorf("Geting key from user, got: %w", err)
//	}
//	decrypted, err := (model.Header).Decrypt(key, model.Body)
//	if err != nil {
//		return fmt.Errorf("Encrypting got: %w", err)
//	}
//	os.WriteFile(c.destPath, decrypted, 0644)
//	return nil
//}

type Router map[string]cmdrouter.Handler

func NewRouter() Router {
	return Router{}
}

func (R Router) Handle(path []string, h cmdrouter.Handler) error {
	p := strings.Join(path, " ")
	if _, ok := R[p]; ok {
		return fmt.Errorf("Key is already exists.")
	}
	R[p] = h 
	return nil
}

func (R Router) HandleFunc(path []string, fn cmdrouter.ProcesserFunc) error {
	p := strings.Join(path, " ")
	if _, ok := R[p]; ok {
		return fmt.Errorf("Key is already exists.")
	}
	R[p] = fn 
	return nil
}


func (R Router) Process(posargs []string) error {
	h, foundOn, err := R.findHandler(posargs)
	if err != nil {
		return err
	}
	posargs = posargs[:foundOn]
	err = h.Process(posargs)
	if err != nil {
		return err
	}
	return nil
}

func (R Router) findHandler(posargs []string) (cmdrouter.Handler, int, error) {
	for  i:=0;i<len(posargs);i++ {
		p := strings.Join(posargs[i:], " ")
		h, ok := R[p]
		if ok {
			return h, i, nil
		}
	}
	return nil, 0, fmt.Errorf("Handler not found")
}

func GetVersion() string {
	return "v0"
}

func VersionCMD(posargs []string) error {
	fmt.Println(GetVersion())
	return nil
}

func GetHelpMsg() string {
	return "Help!"
}

func HelpCMD(posargs []string) error {
	fmt.Println(GetHelpMsg())
	return nil
}
