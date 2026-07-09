package format
//
//import (
//       "io"
//       "os"
//       "fmt"
//       "encoding/binary"
//
//       "crypt/argon2id"
//       "crypt/aes256gcm"
//)
//
//const Magic = "CRPT" 
//const Version = 0
//const HeaderSize int = 128
//
//func GetDefaultHeader() FileHeader {
//	argonHeader := argon2id.GetDefaultHeader()
//	return FileHeader{
//		Magic: [4]byte([]byte(Magic)),
//		Version: int64(Version),
//		IsValid: false, 
//		IsLittleEndian: true,
//		EncryptionFunction: [16]byte([]byte("aes256gcm")),
//		NonceSourceLen: 0, // TODO  
//		ChunkSize: 0, // TODO 
//		ChunksAmount: 0, // TODO 
//		LastChunkSize: 0, // TODO 
//		ArgonParams: argonHeader,
//	}
//}
//
//
//type FileHeader struct {
//	Magic [4]byte // CRPT
//	Version int64 // version as a Timestamp 
//	IsValid bool
//	IsLittleEndian bool
//	EncryptionFunction [16]byte 
//	NonceSourceLen uint16
//	ChunkSize uint16
//	ChunksAmount uint16
//	LastChunkSize uint16
//	ArgonParams argon2id.Header
//}
//
//
//func (F FileHeader) Verify() error {
//	if F.Magic != [4]byte([]byte("CRPT")) {
//		return fmt.Errorf("Invalid magic number.")
//	}
//	if !F.IsValid {
//		return fmt.Errorf("Format is invalid")
//	}
//	return nil
//}
//
//const (
//	FlagIsValid = 1 << 0 // 1
//	FlagIsLittleEndian = 1 << 1 //2
//
//)
//
//func (F *FileHeader) Encode(data *[128]byte) {
//	start := 0
//	end := start + len(F.Magic) 
//	_ = copy(data[start:end], F.Magic[:])
//
//	start = end
//	end = start + 8 
//	binary.LittleEndian.PutUint64(data[start:end], uint64(F.Version))
//
//	start = end
//	end = start + 1
//	data[start] = 0
//	if F.IsValid {
//		data[start] |= FlagIsValid
//	} 
//	if F.IsLittleEndian {
//		data[start] |= FlagIsLittleEndian
//	}
//	
//	start = end
//	end = start + len(F.EncryptionFunction) 
//	_ = copy(data[start:end], F.EncryptionFunction[:]) 
//
//	start = end
//	end = start + 1
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.NonceSourceLen))
//
//	start = end
//	end = start + 2 
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunkSize))
//
//	start = end
//	end = start + 2 
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunksAmount))
//
//	start = end
//	end = start + 2 
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.LastChunkSize))
//
//	start = end
//	end = start + 34 
//	F.ArgonParams.Encode(data)
//}
//
//func (F *FileHeader) Decode(data *[128]byte) {
//	start := 0
//	end := start + len(F.Magic) 
//	_ = copy(F.Magic[:], data[start:end])
//
//	start = end
//	end = start + 8 
//	F.Version = int64(binary.LittleEndian.Uint64(data[start:end]))
//
//	start = end
//	end = start + 1
//	F.IsValid = (data[start] & FlagIsValid) != 0
//	F.IsLittleEndian = (data[start] & FlagIsLittleEndian) != 0
//
//	start = end
//	end = start + len(F.EncryptionFunction) 
//	_ = copy( F.EncryptionFunction[:], data[start:end]) 
//
//	start = end
//	end = start + 1
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.NonceSourceLen))
//
//	start = end
//	end = start + 2 
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunkSize))
//
//	start = end
//	end = start + 2 
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunksAmount))
//
//	start = end
//	end = start + 2 
//	binary.LittleEndian.PutUint16(data[start:end], uint16(F.LastChunkSize))
//
//	start = end
//	end = start + 2 
//	(F.ArgonParams).Decode(data)
//}
////
////func (F *FileHeader) Read(file *os.File) error {
////
////	err := F.UnmarshalBinary(data []byte) error {
////
////}
//
//type Crypt struct {
//     F FileHeader
//     Src io.Reader
//     Key []byte
//     Salt []byte
//     NonceSource []byte
//}
//
//
//func (C Crypt) Encrypt(dstFile *os.File) error {
//	var header [128]byte
//	// F 
//	(&(C.F)).Encode(&header)
//	n, err := dstFile.Write(header[:])
//	if err != nil {
//		return err
//	}
//	if n != len(header) {
//		return fmt.Errorf("Number of writen bytes and length of header doesnt match.")
//	}
//
//	// F 
//	C.EncryptBody(dstFile)
//
//	r, err := dstFile.Seek(0, io.SeekStart)
//	if err != nil {
//		return err
//	}
//	if r != 0 {
//		return fmt.Errorf("Expected offset to be zero, but got: %d", r)
//	}
//
//	// F 
//	(&(C.F)).Encode(&header)
//	n, err = dstFile.Write(header[:])
//	if err != nil {
//		return err
//	}
//	if n != len(header) {
//		return fmt.Errorf("Number of writen bytes and length of header doesnt match.")
//	}
//	return nil
//}
//
//func (C Crypt) Decrypt(dst io.Writer) error {
//	var header [HeaderSize]byte
//	bytesReaden, err := io.ReadAtLeast(C.Src, header[:], len(header)) 
//	if err != nil {
//		return err
//	}
//	if bytesReaden != HeaderSize {
//		return fmt.Errorf("Should have read %d header bytes, but have read %d bytes", len(header), bytesReaden)
//	}
//
//	(&(C.F)).Decode(&header)
////	if len(nonce) != (C.F).NonceSourceLen {
////		return fmt.Errorf("Invalid nonce source length %d, shoud be %d .", len(nonce), (C.F).NonceSourceLen)
////	}
//	nonceSource := make([]byte, (C.F).NonceSourceLen)
//	bytesReaden, err = io.ReadAtLeast(C.Src, nonceSource, int((C.F).NonceSourceLen)) 
//	if err != nil {
//		return err
//	}
//	if bytesReaden != int((C.F).NonceSourceLen) {
//		return fmt.Errorf("Should have read %d nonce source bytes, but have read %d bytes", (C.F).NonceSourceLen, bytesReaden)
//	}
//	salt := make([]byte, (C.F).ArgonParams.SaltLength)
//	if len(salt) != int((C.F).ArgonParams.SaltLength) {
//		return fmt.Errorf("Invalid salt length %d, shoud be %d .", len(salt), (C.F).ArgonParams.SaltLength)
//	}
//	bytesReaden, err = io.ReadAtLeast(C.Src, salt, int((C.F).ArgonParams.SaltLength))
//	if err != nil {
//		return err
//	}
//	// Unsafe comparison, TODO: replace with functions that check that bytesReaden not negative
//	if uint32(bytesReaden) != (C.F).ArgonParams.SaltLength {
//		return fmt.Errorf("Should have read %d salt bytes, but have read %d bytes", (C.F).ArgonParams.SaltLength, bytesReaden)
//	}
//	
//
//	C.DecryptBody(dst)
//
//	return nil
//}
//
//
//func (C Crypt) EncryptBody(dst *os.File) error {
//     	err := writeBytes(C.Salt, dst)
//	if err != nil {
//	   return fmt.Errorf("Writing salt, got %w", err)
//	}
//	//if len(salt) != F.ArgonParams.SaltLength {}
//
//	err = writeBytes(C.NonceSource, dst)
//	if err != nil {
//	   return fmt.Errorf("Writing nonce source, got %w", err)
//	}
//	//if len(salt) != F.NonceSourceLen {}
//
//	if string(C.F.EncryptionFunction[:]) == "aes256gcm" {
//		err = C.aesEncryptBody()
//		if err != nil {
//			return fmt.Errorf("Encrypting body with aes256gcm, got: %w", err)
//		}
//	} else if string(C.F.EncryptionFunction[:]) == "chacha20poly1305" {
//		//TODO:
//		return fmt.Errorf("Not ready yet") 
//	}
//	return fmt.Errorf("Unknown symmetric encryption function :%s", C.F.EncryptionFunction)
//}
//
//func (C Crypt) aesEncryptBody() error {
//	// TODO: check if boundaries is ok 
//	overhead := aes256gcm.GetOverhead(C.Key, plainData)
//	plainDataChunkSize := C.F.ChunkSize - overhead
//	// TODO: add check if plainDataCunkSize is positive
//	dataBuff := make([]byte, plainDataChunkSize)
//	chunkPosition := 0
//	var lastChunkSize int
//	for {
//		nRead, err := C.Src.Read(dataBuff)
//		if err == io.EOF {
//			C.F.ChunksAmount = uint16(chunkPosition)
//			C.F.LastChunkSize = uint16(lastChunkSize)
//			return nil
//		}
//		if err != nil {
//			return fmt.Errorf("Reading bytes from reader, got: %w", err)
//		}
//		if nRead > 0 {
//			nonce := GenerateNonce(chunkPosition, C.NonceSource)
//			err := aes256gcm.EncryptPtr(C.Key, nonce, plainData, cipherData)
//			if err != nil {
//				return fmt.Errorf("Encrypting with aes256gcm, got: %w", err)
//			}
//			nWriten, err := dst.Write(cipherData)
//			if err != nil {
//				return fmt.Errorf("Writing cipherdata, got: %w",)
//			}
//			if nWriten != len(cipherData) {
//				return fmt.Errorf("Wrote lesser, than needed")
//			}
//			lastCunkSize = nWriten
//
//		} else {
//			nWriten = 0
//		}
//		chunkPosition++
//	}
//	return fmt.Errorf("Expected EOF") 
//
//}
//
//func writeBytes(bytes []byte, f *os.File) error {
//	n, err := dst.Write(bytes)
//	if err != nil {
//		return fmt.Errorf("Writing bytes to file, got: %w", err)
//	}
//	if n != len(bytes) {
//		return fmt.Errorf("Wrote lesser than bytes length.")
//	}
//	return nil
//}
//
//
//func (C Crypt) DecryptBody(dst io.Writer) error {
//	if C.F.EncryptionFunction == "aes256gcm" {
//		err := C.aesDecryptBody()
//		if err != nil {
//			return fmt.Errorf("Decrypting body with aes256gcm, got: %w", err)
//		}
//	} else if F.EncryptionFunction == "chacha20poly1305" {
//		//TODO:
//		return fmt.Errorf("Not ready yet") 
//	}
//	return fmt.Errorf("Unknown symmetric encryption function :%s", F.EncryptionFunction)
//}
//
//func (C Crypt) aesDecryptBody() error {
//	// TODO: check if boundaries is ok 
//	overhead := aes256gcm.GetOverhead(key, plainData)
//	plainDataChunkSize := C.F.ChunkSize - overhead
//	// TODO: add check if plainDataCunkSize is positive
//	cryptBuff := make([]byte, C.F.ChunkSize)
//	chunkPosition := 0
//	var lastChunkSize int
//	for x:=0;x<C.F.ChunksAmount;x++ {
//		//nRead, err := src.Read(cryptBuff)
//		cipherData, err := src.Read(cryptBuff)
//		if err == io.EOF {
//			// TODO: do we return nil here ?
//			return nil
//		}
//		if err != nil {
//			return fmt.Errorf("Reading bytes from reader, got: %w", err)
//		}
//		nonce := GenerateNonce(x, nonceSource)
//		err := aes256gcm.DecryptPtr(key, nonce, cipherData, plainData)
//		if err != nil {
//			return fmt.Errorf("Decrypting with aes256gcm, got: %w", err)
//		}
//		nWriten, err := dst.Write(plainData)
//		if err != nil {
//			return fmt.Errorf("Writing cipherdata, got: %w",)
//		}
//		if nWriten != len(plainData) {
//			return fmt.Errorf("Wrote lesser, than needed")
//		}
//	}
//
//	for {
//		if nRead > 0 {
//			lastCunkSize = nWriten
//		} else {
//			nWriten = 0
//		}
//		chunkPosition++
//	}
//	return fmt.Errorf("Expected EOF") 
//
//}
//
//
//
