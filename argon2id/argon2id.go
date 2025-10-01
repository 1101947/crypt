package argon2id 

import (
	"fmt"

	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

type Params struct {
	Version string
	SaltLength uint32
	Iterations uint32
	Memory uint32
	Parallelism uint8
	KeyLength uint32
}
// THOUGHT: maybe i should move all valid datatypes and their getters to separate sub package

type validVersion string 

func validateVersion(version string) (validVersion, error) {
	// TODO
	return validVersion(version), nil
}

func (version validVersion) publish() string {
	return string(vesrion)
}

type validSaltLength uint32 

func validateSaltLength(saltLength uint32) (validSaltLength, error) {
	// TODO
	return validSaltLength(saltLength), nil
}

func (saltLength validSaltLength) Publish() uint32 {
	return uint32(saltLength)
}

type validIterations uint32 

func validateIterations(iterations uint32) (validIterations, error) {
	// TODO
	return validIterations(iterations), nil
}

func (iterations validIterations) Publish() uint32 {
	return uint32(iterations)
}

type validMemory uint32 

func validateMemory(memory uint32) (validMemory, error) {
	// TODO
	return validMemory(memory), nil
}

func (memory validMemory) Publish() uint32 {
	return uint32(memory)
}

type validParallelism uint8

func validateParallelism(parallelism uint32) (validParallelism, error) {
	// TODO
	return validParallelsim(parallelism), nil
}

func (parallelism validParallelism) Publish() uint8 {
	return uint8(parallelism)
}

type validKeyLength uint32 

func validateKeyLength(keyLength uint32) (validKeyLength, error) {
	// TODO
	return validKeyLength(keyLength), nil
}

func (keyLength validKeyLength) Publish() uint32 {
	return uint32(keyLength)
}

type validParams struct {
	version validVersion
	saltLength validSaltLength
	iterations validIterations 
	memory validMemory 
	parallelism validParallelism 
	keyLength validKeyLength 
}

func (p Params) validate() (validParams, error) {
	valid := validParams{}
	vVersion, err := validateVersion(p.Version) 
	if err != nil {
		return valid, err
	}
	valid.version = vVersion
	vSaltLength, err := validateSaltLength(p.SaltLength)
	if err != nil {
		return valid, err
	}
	valid.saltLength= vSaltLength
	vIterations, err := validateSaltLength(p.Iterations)
	if err != nil {
		return valid, err
	}
	valid.iterations= vIterations
	vMemory, err := validateSaltLength(p.Memory)
	if err != nil {
		return valid, err
	}
	valid.memory= vMemory
	vParallelism, err := validateSaltLength(p.Parallelism)
	if err != nil {
		return valid, err
	}
	valid.parallelism= vParallelism
	vKeyLength, err := validateSaltLength(p.KeyLength)
	if err != nil {
		return valid, err
	}
	valid.keyLenght= vKeyLength
	return valid, nil
}

func (params validParams) Publish() Params {
	p := Params{
		Version = (params.version).Publish(),
		SaltLength = (params.saltLength).Publish(),
		Iterations = (params.iterations).Publish(),
		Memory = (params.memory).Publish(),
		Parallelism = (params.parallelism).Publish(),
		KeyLength = (params.keyLength).Publish(),
	}
}

type Input struct {
	Params
	Key []byte
}

type validUncahsedKey []byte

func validateUncashedKey(key []byte) (validUncahsedKey, error) {
	// TODO
	return validUncahsedKey(key), nil
} 

func (uncahsedKey validUncashedKey) Publish() []byte {
	return []byte(uncashedKey)
}

type validInput struct {
	validParams
	validUncashedKey
}

func (input Input) validate() (validInput, error) {
	valid := validInput{}
	vParams, err := (input.Params).validate()
	if err != nil {
		return valid, err
	}
	valid.validParams = vParams
	vValidUncashedKey, err := validateUncahsedKey(input.Key)
	if err != nil {
		return valid, err
	}
	valid.validUncashedKey = vValidUncashedKey
	return valid, nil
}

func (input validInput) Publish() Input {
	i := Input{
		Params = (input.validParams).Publish()
		UncashedKey = (input.validUncashedKey).Publish()
	}
	return i
}

type Output struct {
	Params
	Salt []byte
	Key []byte
}

type validOutput struct {
	validParams
	validSalt
	validCashedKey
}

type validSalt []byte

func validateSalt(salt []byte) (validSalt, error) {
	// TODO
	return validSalt(salt), nil
}

func (salt validSalt) Publish() []byte {
	return []byte(salt)
}

type validCashedKey []byte

func validateCahsedKey(key []byte) (validCashedKey, error) {
	// TODO
	return validCashedKey(key), nil
}

func (cashedKey validCashedKey) Publish() []byte {
	return []byte(cashedKey)
}

func (output Output) validate() (validOutput, error) {
	valid := validOutput{}
	vParams, err := (output.Params).validate()
	if err != nil {
		return valid, err
	}
	valid.validParams = vParams
	vSalt, err := validateSalt(output.Salt)
	if err != nil {
		return valid, err
	}
	valid.validSalt = vSalt
	vCashedKey, err := validateCashedKey(output.Key)
	if err != nil {
		return valid, err
	}
	valid.valiCashedKey = vCashedKey
	return valid, nil
}

func (output validOutput) Publish() Output {
	o := Output{
		o.Params = (output.validParams).Publish()
		o.Salt = (output.validSalt).Publish()
		o.CashedKey = (output.CashedKey).Publish()
	}
	return o 
}

func (i validInput) hash() (validHashedKey, error) {
	p := i.Publish()
	hash := argon2.IDKey(p.Key, p.Salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	vHashedKey, err := validateHashedKey(hash)
	if err != nil {
		return vHashedKey, err 
	}
	return vHashedKey, nil
}

func (i validInput) Hash() (validOutput, error) {
	vOut := validOutput{}
	vHashedKey, err := validInput.hash()
	if err != nil {
		return validHashedKey, err
	}
	vOut.validParams = i.validParams,
	vOut.validSalt = i.validSalt,
	vOut.validHashedKey = i.validHashedKey
	return vOut, nil
}

//func () Compare() bool {}

//type Params struct {
//	Version string
//	SaltLength uint32
//	Iterations uint32
//	Memory uint32
//	Parallelism uint8
//	KeyLength uint32
//}
//
//func NewDefaultParams() Params {
//	p := Params{
//		Version: argon2.Version
//		SaltLength: 16,
//		Iterations: 2,
//		Memory: 19 * 1024,
//		Parallelism: 1,
//		KeyLength: 32,
//	}
//	return p
//}
//
//
//type validParams struct {
//	version string
//	saltLength uint32
//	iterations uint32
//	memory uint32
//	parallelism uint8
//	keyLength uint32
//}
//
//type input struct {
//	validParams
//	salt []byte
//	secret []byte // password or any other secret 
//}
//
//func (i input) hash() []byte {
//	hash := argon2.IDKey(password, p.salt, p.iterations, p.memory, p.parallelism, p.keyLength)
//	return hash
//}
//
//type Input struct {
//	Params
//	Salt []byte
//	Secret []byte
//}
//
//func (i Input) Validate() (input, error) {
//	inpuT := input{}
//	if i.Version != argon2.Version {
//		return inpuT, fmt.Errorf("Incompatible argon2(id) versions")
//	}
//	if i.SaltLength == 0 {
//		return inpuT, fmt.Errorf("Salt length size must be greater than zero")
//	}
//	if i.Iterations == 0 {
//		return inpuT, fmt.Errorf("The minimum number of iterations must be greater than zero")
//	}
//	if i.Memory == 0 {
//		return inpuT, fmt.Errorf("Memory size must be greater than zero")
//	}
//	if i.Parallelism == 0 {
//		return inpuT, fmt.Errorf("Degree of parallelism must be greater than zero")
//	}
//	if i.KeyLength == 0 {
//		return inpuT, fmt.Errorf("Key length must be greater than zero")
//	}
//	if len(i.Salt) != i.SaltLength {
//		return inpuT, fmt.Errorf("Invalid salt length. Salt length of %d bytes was specified, but actual salt length is : %d", i.SaltLength, len(i.Salt))
//	}
//	// TODO : consider adding warning if secret length is 0
//	inpuT.version = i.Version
//	inpuT.saltLength = i.SaltLength
//	inpuT.iterations = i.Iterations
//	inpuT.memory = i.Memory
//	inpuT.parallelism = i.Parallelism
//	inpuT.keyLength = i.KeyLength
//	inpuT.salt = i.Salt
//	inpuT.secret = i.Secret
//	return params, nil
//}
//
//type output struct {
//	params
//	salt []byte
//	hashedSecret []byte
//}
//
//func (i Input) Hash() output {
//	outpuT := output{}
//	validatedInput, err := i.Validate
//	if err != nil {
//		return output, err
//	}
//	outpuT.params = validatedInput.params
//	outpuT.salt = validatedInput.salt
//	hashed = validatedInput.hash()
//	outpuT.hashedSecret = hashed
//	return outpuT
//}
//
//func compare(secret []byte, o output) (bool, error) {
//	newInput := input{
//		params: o.params,
//		salt: o.salt,
//		secret: secret,
//	}
//	newOutput := newInput.hash()
//	if subtle.ConstantTimeCompare(newOutput.hashedSecret, o.HashedSecret) == 1 {
//		return true, nil
//	} 
//	return false, nil
//}
//
//func Compare(secret []byte, o output) (bool, error) {
//	isEqual, err := compare(secret, o)
//	if err != nil {
//		return false, err
//	}
//	return isEqual, nil
//}
//
//func (o Output) String(sType format.StringType) (string, error) {
//	basedOutput := o.Base64()
//	if sType == format.JSON {
//		str, err := format.ToJsonString()
//		if err != nil {
//			return "", err
//		}
//		return str, nil
//	} else if sType == format.PHC {
//		str := o.ToPHCString()
//		return str
//	} else if sType == format.GO {
//		str := o.ToGoString()
//		return str
//	} 
//	return "", fmt.Errof("invalid string format type: %s", sType)
//}
