package main
//
import (
	"io"
	"os"
	"fmt"
//	//"bufio"
//	//"strings"
////	"encoding/json"
//	"crypto/rand"
////	"crypt/encrypted"
////	"crypt/argon2id"
//	"crypt/format"
//
//	"golang.org/x/term"
//	//"github.com/1101947/cliargumentrouter/cmdrouter"
	"github.com/1101947/cliargumentrouter/flag"
)
//
type CryptHandler struct {
	cryptData cryptData
	interactive string
}
//

type EncryptHandler CryptHandler

func NewEncryptHandler() EncryptHandler {
	c := NewCryptData()
	return EncryptHandler{
		cryptData: c,
		interactive: "false",
	}
}

type DecryptHandler CryptHandler

func NewDecryptHandler() DecryptHandler {
	c := NewCryptData()
	return DecryptHandler{
		cryptData: c,
		interactive: "false",
	}
}


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

	// TODO: uncomment later
	//err = E.cryptData.Encrypt()
	//return err
	fmt.Println("Encrypting...")
	return nil

	//err := c.Decrypt()
}
//
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


	//key, err  := GetKey()
	//if err != nil {
	//	return fmt.Errorf("Geting key from user, got: %w", err)
	//}

	//header := format.GetNewHeader()
	//header.Decrypt(input, output, key)
	fmt.Println("Decrypting...")
	return nil
}
//
//
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
//
//func (c cryptData) Encrypt() error {
//	if c.input == nil {
//		return fmt.Errorf("Input is not set")
//	}
//	if c.output == nil {
//		return fmt.Errorf("Input is not set")
//	}
////	data, err := io.ReadAll(c.input)
////	if err != nil {
////		return fmt.Errorf("Trying to read file, got: %w", err)
////	}
//
////	salt, err := GenSalt(int(c.slen))
////	if err != nil {
////		return err
////	}
//	key, err  := GetKey()
//	if err != nil {
//		return fmt.Errorf("Geting key from user, got: %w", err)
//	}
//
//	header := format.Header{}
//	err := header.Encrypt(input, output, key)
//	if err != nil {
//		return err
//	}
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
