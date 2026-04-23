package argon2id

import (
	"flag"
	"fmt"

	"crypt/general"
	"crypt/cli/get_password"
	"crypt/rand"
	"crypt/general/bytesToString"

)

type PtrParams struct {
	SaltLength *uint
	Iterations *uint
	Memory *uint
	Parallelism *uint
	KeyLength *uint
}


func ArgonParamsFromCLIFlags(defaults Params) PtrParams {
	//argon2idHashCMD := flag.NewFlagSet("argon2id hash", flag.ExitOnError)
	ptrSaltLength := flag.Uint("salt_len", uint(defaults.SaltLength), "length of salt")
	ptrIterations := flag.Uint("iterations", uint(defaults.Iterations), "number of iterations")
	ptrMemory := flag.Uint("memory", uint(defaults.Memory), "memory size")
	ptrParallelism := flag.Uint("parallelism", uint(defaults.Parallelism), "degree of parallelism")
	ptrKeyLength := flag.Uint("key_length", uint(defaults.KeyLength), "length of kdf output key")
	paramsToReturn := PtrParams{
		SaltLength: ptrSaltLength,
		Iterations: ptrIterations,
		Memory: ptrMemory,
		Parallelism: ptrParallelism,
		KeyLength: ptrKeyLength,
	}
	return paramsToReturn
}

func NewParamsFromPointers(ptr PtrParams) (Params, error) {
	// check that ptr value is asignable less than uint32 or uint8
	params := Params{}
	s, err := general.UintToUint32(*ptr.SaltLength)
	if err != nil {
		return params, err
	}
	i, err := general.UintToUint32(*ptr.Iterations)
	if err != nil {
		return params, err
	}
	m, err := general.UintToUint32(*ptr.Memory)
	if err != nil {
		return params, err
	}
	p, err := general.UintToUint8(*ptr.Parallelism)
	if err != nil {
		return params, err
	}
	k, err := general.UintToUint32(*ptr.KeyLength)
	if err != nil {
		return params, err
	}
	params.SaltLength = s
	params.Iterations = i 
	params.Memory = m 
	params.Parallelism = p 
	params.KeyLength = k 
	return params, nil
}


func RunCLI() error {
	argonDefaults := NewDefaultParams()
	ptrParams := ArgonParamsFromCLIFlags(argonDefaults)
	flag.Parse()
	params, err := NewParamsFromPointers(ptrParams)
	if err != nil {
		return err
	}
	password, err := get_password.GetPassword() 
	if err != nil {
		return err
	}
	salt, err := rand.Salt(params.SaltLength)
	if err != nil {
		return err
	}
	validParamS, err := params.Validate()
	if err != nil {
		return err
	}
	hashedBytes, err := Hash(password, salt, validParamS)
	hashed, err := bytesToString.BytesToString(hashedBytes, bytesToString.Base64)
	if err != nil {
		return err
	}
	fmt.Println(hashed)
	return nil
}
