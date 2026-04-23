package argon2id

import ()

type StringType string

const (
	JSON StringType = "json"
	PHC StringType = "phc"
	GO StringType = "go"
)

type StringedOutput struct {
	params
	salt string
	hashedSecret string
}

func (o output) ToStringBytes() StringedOutput {
	s := StringedOutput{
		params: o.params,
		salt: base64.RawStdEncoding.EncodeToString(o.salt)
		hashedSecret: base64.RawStdEncoding.EncodeToString(o.hashedSecret)
	}
	return s
}

func (o output) ToString(sType stringType) string {
	stringed := o.ToStringBytes()
	if typE
}



func (o output) ToPHCString() string {
	b64Salt := base64.RawStdEncoding.EncodeToString(o.salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(o.hashedSecret)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", o.version, o.memory, o.iterations, o.parallelism, b64Salt, b64Hash)
}

func (o output) ToJsonString() string {
	toJson := struct{
		Params Params
		Salt string 
		HashedSecret string 
	}{
		Params: o.params,
		Salt: o.salt
		HashedSecret: o.hashedSecret,
	}
}

func (o output) ToGoString() string {}
