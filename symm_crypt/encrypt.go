package symm_crypt 
//
//import (
//	"YSNP2/argon2id"
//	"YSNP2/aes256gcm"
//)
//
//func Encrypt(password, data []byte,  pSaltLength uint32, pIterations uint32, pMemory uint32, pParallelism uint8, pKeyLength uint32) ([]byte, error) {
//	params := argon2id.NewParams(pSaltLength, pIterations, pMemory, pParallelism, pKeylength)
//	salt, err := rand.Salt(params.GetSaltLength)
//	if err != nil {
//		return nil, err
//	}
//	key, err := argon2id.Hash(password, salt, params)
//	if err != nil {
//		return nil, err
//	}
//	encrypted, err := aes256gcm.Encrypt(key, data)
//	if err != nil {
//		return nil, err
//	}
//	return encrypted, err
//}
