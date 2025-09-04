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

func NewDefaultParams() Params {
	p := Params{
		Version: argon2.Version
		SaltLength: 16,
		Iterations: 2,
		Memory: 19 * 1024,
		Parallelism: 1,
		KeyLength: 32,
	}
	return p
}


type validParams struct {
	version string
	saltLength uint32
	iterations uint32
	memory uint32
	parallelism uint8
	keyLength uint32
}

type input struct {
	validParams
	salt []byte
	secret []byte // password or any other secret 
}

func (i input) hash() []byte {
	hash := argon2.IDKey(password, p.salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

type Input struct {
	Params
	Salt []byte
	Secret []byte
}

func (i Input) Validate() (input, error) {
	inpuT := input{}
	if i.Version != argon2.Version {
		return inpuT, fmt.Errorf("Incompatible argon2(id) versions")
	}
	if i.SaltLength == 0 {
		return inpuT, fmt.Errorf("Salt length size must be greater than zero")
	}
	if i.Iterations == 0 {
		return inpuT, fmt.Errorf("The minimum number of iterations must be greater than zero")
	}
	if i.Memory == 0 {
		return inpuT, fmt.Errorf("Memory size must be greater than zero")
	}
	if i.Parallelism == 0 {
		return inpuT, fmt.Errorf("Degree of parallelism must be greater than zero")
	}
	if i.KeyLength == 0 {
		return inpuT, fmt.Errorf("Key length must be greater than zero")
	}
	if len(i.Salt) != i.SaltLength {
		return inpuT, fmt.Errorf("Invalid salt length. Salt length of %d bytes was specified, but actual salt length is : %d", i.SaltLength, len(i.Salt))
	}
	// TODO : consider adding warning if secret length is 0
	inpuT.version = i.Version
	inpuT.saltLength = i.SaltLength
	inpuT.iterations = i.Iterations
	inpuT.memory = i.Memory
	inpuT.parallelism = i.Parallelism
	inpuT.keyLength = i.KeyLength
	inpuT.salt = i.Salt
	inpuT.secret = i.Secret
	return params, nil
}

type output struct {
	params
	salt []byte
	hashedSecret []byte
}

func (i Input) Hash() output {
	outpuT := output{}
	validatedInput, err := i.Validate
	if err != nil {
		return output, err
	}
	outpuT.params = validatedInput.params
	outpuT.salt = validatedInput.salt
	hashed = validatedInput.hash()
	outpuT.hashedSecret = hashed
	return outpuT
}

func (o output) ToPHCString() string {
	b64Salt := base64.RawStdEncoding.EncodeToString(o.salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(o.hashedSecret)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", o.version, o.memory, o.iterations, o.parallelism, b64Salt, b64Hash)
}
//
//func FromStringToPHC(s string) output {
//}

func compare(secret []byte, o output) (bool, error) {
	newInput := input{
		params: o.params,
		salt: o.salt,
		secret: secret,
	}
	newOutput := newInput.hash()
	if subtle.ConstantTimeCompare(newOutput.hashedSecret, o.HashedSecret) == 1 {
		return true, nil
	} 
	return false, nil
}

func Compare(secret []byte, o output) (bool, error) {
	isEqual, err := compare(secret, o)
	if err != nil {
		return false, err
	}
	return isEqual, nil
}

