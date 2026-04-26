package main

import (
	"io"
	"os"
	"fmt"
	//"bufio"
	//"strings"
	"encoding/json"
	"crypto/rand"
	"crypt/encrypted"
	"crypt/argon2id"

	"golang.org/x/term"
	//"github.com/1101947/cliargumentrouter/cmdrouter"
	"github.com/1101947/cliargumentrouter/flag"
)

type CryptHandler struct {
	cryptData cryptData
	interactive string
}

func NewEncryptHandler() EncryptHandler {
	c := NewCryptData()
	return EncryptHandler{
		cryptData: c,
		interactive: "false",
	}
}

type EncryptHandler CryptHandler

func NewDecryptHandler() DecryptHandler {
	c := NewCryptData()
	return DecryptHandler{
		cryptData: c,
		interactive: "false",
	}
}

type DecryptHandler CryptHandler

func (E EncryptHandler) Process(posargs []string) error {
	// TODO: maybe put flags inside EncryptionHandler ?
	flags := flag.DefaultFlags("--", "=", posargs)
	err := flags.Parse()
	if err != nil {
		return fmt.Errorf("Parsing cli arguments, got: %w", err)
	}
	kwargs, posargs := flags.Extract()
	inputVals, ok := kwargs["input"]
	if !ok {
		return fmt.Errorf("Input argument must be specified.")
	}
	if len(inputVals) != 1 {
		return fmt.Errorf("Only one input argument must be specified.")
	}
	var input string
	for _, v := range inputVals {
		input = v
		break
	}
	// TODO: should i add some verification os.Stat(); !os.IsNotExist(), file.IsDir() ?
	inputRD, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("Trying to open file, got : %w", err)
	}
	defer inputRD.Close()
	E.cryptData.input = inputRD

	outputVals, ok := kwargs["output"]
	if !ok {
		return fmt.Errorf("Output argument must be specified.")
	}
	if len(outputVals) != 1 {
		return fmt.Errorf("Only one output argument must be specified.")
	}
	var output string
	for _, v := range outputVals {
		output = v
		break
	}
	outputWR, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("Trying to create file, got : %w", err)
	}
	defer outputWR.Close()
	E.cryptData.output = outputWR 

	
	//fmt.Println("Encrypt: ")
	//fmt.Printf("Enter source path: ")
	//reader := bufio.NewReader(os.Stdin)
	//sp, _ := reader.ReadString('\n')
	//sp = strings.TrimSpace(sp)
	//fmt.Printf("Enter destination path: ")
	//dp, _ := reader.ReadString('\n')
	//dp = strings.TrimSpace(dp)
	//c := cryptData{
	//	sourcePath: sp,
	//	destPath: dp,
	//	symmCryptFuncToUse: "aes256gcm", 
	//	slen: 16, 
	//	iter: 1, 
	//	mem: 64*1024,
	//	klen: 32, 
	//	paral: 4, 
	//}
	err = E.cryptData.Encrypt()

	//err := c.Decrypt()
	return err
}

func (D DecryptHandler) Process(posargs []string) error {
	// TODO: maybe put flags inside EncryptionHandler ?
	flags := flag.DefaultFlags("--", "=", posargs)
	err := flags.Parse()
	if err != nil {
		return fmt.Errorf("Parsing cli arguments, got: %w", err)
	}
	kwargs, posargs := flags.Extract()
	inputVals, ok := kwargs["input"]
	if !ok {
		return fmt.Errorf("Input argument must be specified.")
	}
	if len(inputVals) != 1 {
		return fmt.Errorf("Only one input argument must be specified.")
	}
	var input string
	for _, v := range inputVals {
		input = v
		break
	}
	// TODO: should i add some verification os.Stat(); !os.IsNotExist(), file.IsDir() ?
	inputRD, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("Trying to open file, got : %w", err)
	}
	defer inputRD.Close()
	D.cryptData.input = inputRD

	outputVals, ok := kwargs["output"]
	if !ok {
		return fmt.Errorf("Output argument must be specified.")
	}
	if len(outputVals) != 1 {
		return fmt.Errorf("Only one output argument must be specified.")
	}
	var output string
	for _, v := range outputVals {
		output = v
		break
	}
	outputWR, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("Trying to create file, got : %w", err)
	}
	defer outputWR.Close()
	D.cryptData.output = outputWR 


	//fmt.Println("Encrypt: ")
	//fmt.Printf("Enter source path: ")
	//reader := bufio.NewReader(os.Stdin)
	//sp, _ := reader.ReadString('\n')
	//sp = strings.TrimSpace(sp)
	//fmt.Printf("Enter destination path: ")
	//dp, _ := reader.ReadString('\n')
	//dp = strings.TrimSpace(dp)
	//c := cryptData{
	//	sourcePath: sp,
	//	destPath: dp,
	//	symmCryptFuncToUse: "aes256gcm", 
	//	slen: 16, 
	//	iter: 1, 
	//	mem: 64*1024,
	//	klen: 32, 
	//	paral: 4, 
	//}
	//err := c.Encrypt()
	err = D.cryptData.Decrypt()
	return err
}


type cryptData struct {
	//sourcePath string
	//destPath string
	input io.Reader
	output io.Writer
	symmCryptFuncToUse string
	slen uint32
	iter uint32
	mem uint32
	klen uint32
	paral uint8
}

func NewCryptData() cryptData {
	c := cryptData{
		input: nil,
		output: nil,
		symmCryptFuncToUse: "aes256gcm", 
		slen: 16, 
		iter: 1, 
		mem: 64*1024,
		klen: 32, 
		paral: 4, 
	}
	return c
} 

func (c cryptData) Encrypt() error {
	if c.input == nil {
		return fmt.Errorf("Input is not set")
	}
	if c.output == nil {
		return fmt.Errorf("Input is not set")
	}
	data, err := io.ReadAll(c.input)
	if err != nil {
		return fmt.Errorf("Trying to read file, got: %w", err)
	}
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
	c.output.Write(encrptd)
	//os.WriteFile(c.destPath, encrptd, 0644)
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
	if c.input == nil {
		return fmt.Errorf("Input is not set")
	}
	if c.output == nil {
		return fmt.Errorf("Input is not set")
	}

	//jsonData, err := os.ReadFile(c.sourcePath)
	jsonData, err := io.ReadAll(c.input)
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
	//os.WriteFile(c.destPath, decrypted, 0644)
	c.output.Write(decrypted)
	return nil
}
