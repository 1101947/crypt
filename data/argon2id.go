package data

import (
	"YSNP2/argon2id"
)

func ToString(salt []byte, saltLength uint32, iterations uint32, memory uint32, parallelism uint8, keyLength uint32) string {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt) 
	str := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, b64Salt)
	return str
}
