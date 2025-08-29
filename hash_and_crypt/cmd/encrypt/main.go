package main

import (
	"encoding/base64"
	"flag"
	"fmt"

	"YSNP2/hash_and_crypt"
	"YSNP2/kdf"
	"YSNP2/symm_crypt"
	"YSNP2/argon2id"
	"YSNP2/rand"
)

type printer string

const (
	printBytes printer = "bytes"
	printBase64 printer = "base64"
)

func cli() ((hash_and_crypt.CryptoInput), printer, error) {
	argonParams := argon2id.NewDefaultParams()
	ptrPrinter := flag.String("print_as", "base64", "How to print encrypted data")
	ptrSymmCryptName := flag.String("symm_crypt", "aes256gcm", "encryption and decryption function" )
	ptrKdfName := flag.String("kdf", "argon2id", "a key derivation function")
	ptrSaltLength := flag.Uint("salt_length", uint(argonParams.SaltLength), "length of sallt for argon2id key derivation function"  )
	// TODO: add description
	ptrIterations := flag.Uint("iterations", uint(argonParams.Iterations), "")
	ptrMemory := flag.Uint("memory", uint(argonParams.Memory), "How much memory argon2id key derivation function will use")
	ptrParallelism := flag.Uint("parallelism", uint(argonParams.Parallelism), "How many threads argon2id key derivation function will use.")
	// TODO: add description
	ptrKeyLength := flag.Uint("key_length", uint(argonParams.KeyLength), "")
	ptrPassword := flag.String("password", "", "password (input key) for key derivation function") 
	ptrData := flag.String("data", "", "data to encrypt, for symmetric key algorithm function") 
	ptrSaltBytes := flag.String("saltBytes", "", "salt in default go bytes print representation")
	ptrSaltBase64 := flag.String("saltBase64", "", "salt in base64") 
	flag.Parse()

	cryptIn := hash_and_crypt.CryptoInput{}
	argonParams.SaltLength = uint32(*ptrSaltLength)
	argonParams.Iterations = uint32(*ptrIterations) 
	argonParams.Memory = uint32(*ptrMemory) 
	argonParams.Parallelism = uint8(*ptrParallelism) 
	argonParams.KeyLength = uint32(*ptrKeyLength) 
	whyPassInvalid := whyPasswordInvalid(*ptrPassword)
	if whyPassInvalid != nil {
		err := fmt.Errorf("%v", whyPasswordInvalid)
		return cryptIn, printer(*ptrPrinter), err 
	}
	cryptIn.ReturnCryptoKey = false
	cryptIn.InputKey = []byte(*ptrPassword)
	cryptIn.Data = []byte(*ptrData)
	if *ptrKdfName == "argon2id" {
		//p := argonParams
		kdfParams := kdf.Argon2idParams{}
		kdfParams.P = argonParams
		cryptIn.Kdf = kdfParams
	} else {
		err := fmt.Errorf("Ivalid key derivation function: %s", *ptrKdfName)
		return cryptIn, printer(*ptrPrinter), err 
	}
	if *ptrSymmCryptName == "aes256gcm" {
		cryptIn.Crypter = symm_crypt.Aes256_gcm{}
	} else {
		err := fmt.Errorf("Ivalid symmetric key algorithm function: %s", *ptrSymmCryptName)
		return cryptIn, printer(*ptrPrinter), err 
	}
	if *ptrSaltBase64 != "NoSalt" {
		if *ptrSaltBytes != "" {
			err := fmt.Errorf("Encounter two salts: in base64: %s and in bytes: %v", *ptrSaltBase64, *ptrSaltBytes)
			return cryptIn, printer(*ptrPrinter), err 
		}
		salt, err := base64.RawStdEncoding.Strict().DecodeString(*ptrSaltBase64)
		if err != nil {
			return cryptIn, printer(*ptrPrinter), err 
		}
		cryptIn.Salt = salt
	} else if *ptrSaltBytes != "" {
		if *ptrSaltBase64 != "noSalt" {
			err := fmt.Errorf("Encounter two salts: in base64: %s and in bytes: %v", *ptrSaltBase64, *ptrSaltBytes)
			return cryptIn, printer(*ptrPrinter), err 
		}
		var salt []byte
		_, err := fmt.Scanf("%v", &salt)
		if err != nil {
			return cryptIn, printer(*ptrPrinter), err 
		}
		cryptIn.Salt = salt
	} else {
		if *ptrKdfName == "argon2id" {
			salt, err := rand.Salt(uint32(*ptrSaltLength))
			if err != nil {
				return cryptIn, printer(*ptrPrinter), err 
			}
			cryptIn.Salt = salt
		} else {
			return cryptIn, printer(*ptrPrinter), fmt.Errorf("salt length is unknown for %s key derivation function", *ptrKdfName)
		}
	} 
	return cryptIn, printer(*ptrPrinter), nil 
}

func whyPasswordInvalid(password string) error {
	if len(password) < 1 {
		return fmt.Errorf("password should be at least on symbol length")
	}
	return nil
}

func printCryptOutput(c hash_and_crypt.CryptoOutput, p printer) string {
	if p == printBytes {
		return fmt.Sprintf("%v", c.Crypted)
	} 
	return base64.RawStdEncoding.EncodeToString(c.Crypted)
}

func run() (string, error) {
	cryptIn, printer, err := cli()
	if err != nil {
		return "", err
	}
	cryptOut, err := hash_and_crypt.Encrypt(cryptIn)
	encoded := printCryptOutput(cryptOut, printer)
	return encoded, nil
}

func main() {
	crypted, err := run()
	if err != nil {
		fmt.Println(err)
		return 
	}
	fmt.Println(crypted)
}
