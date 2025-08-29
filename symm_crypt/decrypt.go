package symm_crypt 
//
//import (
//)
//
//func Decrypt(data, password []byte, pSaltLength uint32, pIterations uint32, pMemory uint32, pParallelism uint8, pKeyLength uint32) ([]byte, error){
//		params := argon2id.NewParams(pSaltLength, pIterations, pMemory, pParallelism, pKeylength)
//	salt, err := rand.Salt(params.GetSaltLength)
//	if err != nil {
//		return nil, err
//	}
//	key, err := argon2id.Hash(password, salt, params)
//	if err != nil {
//		return nil, err
//	}
//	decrypted, err := aes256-gcm.Decrypt(key, data)
//	if err != nil {
//		return nil, err
//	}
//	return decrypt, err
//}
