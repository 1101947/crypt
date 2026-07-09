package format 
//
//import (
//	"fmt"
//	"os"
//)
//
//// length of chunk = noncelength(12bytes) + plaindata chunk length
//type CryptBody struct {
//	nonceLen int
//	cryptChunkLen int
//	lastChunkLen int
//	chunksAmount int
//	key []byte
//	nonceSource []byte
//	in, out *File
//}
//
//func (C CryptBody) EncryptBodyAes() error {
//	// TOFIX:
//	if nonceLen != 12 {
//		return fmt.Errorf("Error: nonce length is not 12 !. This will be fixed in the future.")
//	}
//	plainChunkLen = cryptChunkLen - nonceLen 
//	plainDataBuf = make([]byte, plainChunkLen)
//	cryptDataBuf = make([]byte, cryptChunkLen)
//	C.lastChunkLen = 0
//	C.chunksAmount = 0
//	for {
//		plainBytesRead, err := in.Read(plainDataBuf)
//		if plainBytesRead > 0 {
//			err := Encrypt(key, nonceSource, plainDataBuf, cryptDataBuf)
//			if err != nil {
//				return fmt.Errorf("Encrypting chunk, got: %w", err)
//			}
//		} else {
//			return fmt.Errorf("Error: plainBytesRead must be greater than zero")
//		}
//		_, err = out.Write(cryptDataBuf)
//		if err != nil {
//			return fmt.Errorf("Writing cryptChunk to file, got: %w", err)
//		}
//		C.chunksAmount++
//	}
//	C.lastChunkLen = plainBytesRead + nonceLen
//	return nil
//}
////
////func (C CryptBody) DecryptBodyAes() error {
////	// TOFIX:
////	if nonceLen != 12 {
////		return fmt.Errorf("Error: nonce length is not 12 !. This will be fixed in the future.")
////	}
////	plainChunkLen = cryptChunkLen - nonceLen 
////	plainDataBuf = make([]byte, plainChunkLen)
////	cryptDataBuf = make([]byte, cryptChunkLen)
////	C.lastChunkLen = 0
////	C.chunksAmount = 0
////	Crypt cryptChunk = Crypt{
////		In: 
////	}
////	for {
////		cryptBytesRead, err := in.Read(cryptDataBuf)
////		if cryptBytesRead > 0 {
////			err := DecryptAes()
////			if err != nil {
////				return fmt.Errorf("Encrypting chunk, got: %w", err)
////			}
////		}
////		_, err = out.Write(cryptDataBuf)
////		if err != nil {
////			return fmt.Errorf("Writing cryptChunk to file, got: %w", err)
////		}
////		C.chunksAmount++
////	}
////	C.lastChunkLen = plainBytesRead + nonceLen
////	return nil
////}
