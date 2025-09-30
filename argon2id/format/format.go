package format

import (
	"crypt/argon2id"
)


type StringType string

const (
	JSON StringType = "json"
	PHC StringType = "phc"
	GO StringType = "go"
)

type StringedOutput struct {
	Params argon2id.Params
	Salt string
	HashedSecret string
}

func (o Output) Base64() StringedOutput {
	s := StringedOutput{
		Params: o.Params,
		Salt: base64.RawStdEncoding.EncodeToString(o.Salt)
		CashedSecret: base64.RawStdEncoding.EncodeToString(o.HashedSecret)
	}
	return s
}


func (o StringedOutput) ToPHCString() string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", o.Version, o.Memory, o.Iterations, o.Parallelism, o.Salt, o.HashedSecret)
}

func (o output) ToJsonString() (string, error) {
	result, err := json.Marshal(*o)
	if err != nil {
		return "", err
	}
	return result, nil
}

func (o output) ToGoString() string {
	return fmt.Sprintf("%v", o)
}
