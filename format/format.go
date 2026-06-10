package format

import (
       "io"
       "os"
       "fmt"
       "encoding/binary"

       "crypt/argon2id"
)

// Steam for streaming - each chunk have length field.
// type Stream struct {}

// File for storing encrypted data as files. Chunk size, amount of chunks, size of lenght chunk(1 < size of last chunk < chunk size) specified in header.
// type File struct {}

// Escaped - not shure if it have any usecase, mabe for storing in popular serialization formats like json, yaml
// type Escaped

// structure:
/* 
Header:
	Magic
	Version
	IsValid
	IsLittleEndian bool
	EncryptionFunction [16]byte 
	NonceSourceLen uint8
	ChunkSize uint8
	ChunksAmount uint8
	LastChunkSize uint8
	ArgonParams argon2id.Header
Body:
	Salt
	Nonce
	Chunk1
	...
	ChunkN
	LastChunk
*/


const Magic = "CRPT" 
const Version = 0
const HeaderSize int = 128

func GetDefaultHeader() FileHeader {
	argonHeader := argon2id.GetDefaultHeader()
	return FileHeader{
		Magic: [4]byte([]byte(Magic)),
		Version: int64(Version),
		IsValid: false, 
		IsLittleEndian: true,
		EncryptionFunction: [16]byte([]byte("aes256gcm")),
		NonceSourceLen: 0, // TODO  
		ChunkSize: 0, // TODO 
		ChunksAmount: 0, // TODO 
		LastChunkSize: 0, // TODO 
		ArgonParams: argonHeader,
	}
}


type FileHeader struct {
	Magic [4]byte // CRPT
	Version int64 // version as a Timestamp 
	IsValid bool
	IsLittleEndian bool
	EncryptionFunction [16]byte 
	NonceSourceLen uint16
	ChunkSize uint16
	ChunksAmount uint16
	LastChunkSize uint16
	ArgonParams argon2id.Header
}


func (F FileHeader) Verify() error {
	if F.Magic != [4]byte([]byte("CRPT")) {
		return fmt.Errorf("Invalid magic number.")
	}
	if !F.IsValid {
		return fmt.Errorf("Format is invalid")
	}
	return nil
}

const (
	FlagIsValid = 1 << 0 // 1
	FlagIsLittleEndian = 1 << 1 //2

)

func (F *FileHeader) Encode(data *[128]byte) {
	start := 0
	end := start + len(F.Magic) 
	_ = copy(data[start:end], F.Magic[:])

	start = end
	end = start + 8 
	binary.LittleEndian.PutUint64(data[start:end], uint64(F.Version))

	start = end
	end = start + 1
	data[start] = 0
	if F.IsValid {
		data[start] |= FlagIsValid
	} 
	if F.IsLittleEndian {
		data[start] |= FlagIsLittleEndian
	}
	
	start = end
	end = start + len(F.EncryptionFunction) 
	_ = copy(data[start:end], F.EncryptionFunction[:]) 

	start = end
	end = start + 1
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.NonceSourceLen))

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunkSize))

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunksAmount))

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.LastChunkSize))

	start = end
	end = start + 34 
	F.ArgonParams.Encode(data)
}

func (F *FileHeader) Decode(data *[128]byte) {
	start := 0
	end := start + len(F.Magic) 
	_ = copy(F.Magic[:], data[start:end])

	start = end
	end = start + 8 
	F.Version = int64(binary.LittleEndian.Uint64(data[start:end]))

	start = end
	end = start + 1
	F.IsValid = (data[start] & FlagIsValid) != 0
	F.IsLittleEndian = (data[start] & FlagIsLittleEndian) != 0

	start = end
	end = start + len(F.EncryptionFunction) 
	_ = copy( F.EncryptionFunction[:], data[start:end]) 

	start = end
	end = start + 1
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.NonceSourceLen))

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunkSize))

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.ChunksAmount))

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.LastChunkSize))

	start = end
	end = start + 2 
	(F.ArgonParams).Decode(data)
}
//
//func (F *FileHeader) Read(file *os.File) error {
//
//	err := F.UnmarshalBinary(data []byte) error {
//
//}


type Crypt strcut {
     F FileHeader
     Src io.Reader
     Key []byte
}

func (F FileHeader) Encrypt(src io.Reader, dstFile string, key []byte ) error {
	f, err := os.Create(dstFile)
	if err != nil {
		return fmt.Errorf("Creating file, got: %w", err)
	}
	defer f.Close()

	var header [128]byte
	(&F).Encode(&header)
	n, err := f.Write(header[:])
	if err != nil {
		return err
	}
	if n != len(header) {
		return fmt.Errorf("Number of writen bytes and length of header doesnt match.")
	}

	F.EncryptBody(input, key)

	n, err := f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("Expected offset to be zero, but got: %d", n)
	}

	(*F).Encode(*header)
	n, err := f.Write(header[:])
	if err != nil {
		return err
	}
	if n != len(header) {
		return fmt.Errorf("Number of writen bytes and length of header doesnt match.")
	}
	return nil
}

func (F FileHeader) Decrypt(src io.Reader, dst io.Writer, key []byte) error {
	var header [HeaderSize]byte
	bytesReaden, err := io.ReadAtLeast(src, header[:], len(header)) 
	if err != nil {
		return err
	}
	if bytesReaden != HeaderSize {
		return fmt.Error("Should have read %d header bytes, but have read %d bytes", len(header), bytesReader)
	}

	(*F.FileHeader).Decode(*header)
	if len(nonce) != F.NonceSourceLen {
		return fmt.Errorf("Invalid nonce source length %d, shoud be %d .", len(nonce), F.NonceSourceLen)
	}
	nonceSource := make([]byte, F.NonceSourceLen)
	bytesReaden, err := io.ReadAtLeast(src, nonceSource, F.NonceSourceLen) 
	if err != nil {
		return err
	}
	if bytesReaden != F.NonceSourceLen {
		return fmt.Error("Should have read %d nonce source bytes, but have read %d bytes", F.NonceSourceLen, bytesReader)
	}


	if len(salt) != F.ArgonParams.SaltLength {
		return fmt.Errorf("Invalid salt length %d, shoud be %d .", len(salt), F.ArgonParams.SaltLength)
	}
	salt := make([]byte, F.ArgonParams.SaltLength)
	bytesReaden, err := io.ReadAtLeast(src, salt, F.ArgonParams.SaltLength) 
	if err != nil {
		return err
	}
	if bytesReaden != F.ArgonParams.SaltLength {
		return fmt.Error("Should have read %d salt bytes, but have read %d bytes", F.ArgonParams.SaltLength, bytesReader)
	}
	

	F.DecryptBody(src, dst, key)

	return nil
}


func (F FileHeader) EncryptBody(src io.Reader, dst *os.File, key, salt, nonceSource []byte) {
	n, err := dst.Write(salt)
	if err != nil {
		return fmt.Errorf("Writing salt, got: %w", err)
	}
	if n != len(salt) {
		return fmt.Errorf("Wrote lesser than salt length.")
	}
	//if len(salt) != F.ArgonParams.SaltLength {}

	n, err := dst.Write(nonceSource)
	if err != nil {
		return fmt.Errorf("Writing nonce source, got: %w", err)
	}
	if n != len(nonceSource) {
		return fmt.Errorf("Wrote lesser than nonce source length.")
	}
	//if len(salt) != F.NonceSourceLen {}

	if F.EncryptionFunction == "aes256gcm" {
		// TODO: check if boundaries is ok 
		overhead := aes256gcm.GetOverhead(key, plainData)
		plainDataChunkSize := F.ChunkSize - overhead
		// TODO: add check if plainDataCunkSize is positive
		dataBuff := make([]byte, plainDataChunkSize)
		chunkPosition := 0
		var lastChunkSize int
		for {
			nRead, err := src.Read(dataBuff)
			if err == io.EOF {
				F.ChunksAmount = chunkPosition
				F.LastChunkSize = lastChunkSize
				return nil
			}
			if err != nil {
				return fmt.Errorf("Reading bytes from reader, got: %w", err)
			}
			if nRead > 0 {
				nonce := GenerateNonce(chunkPosition, nonceSource)
				err := aes256gcm.EncryptPtr(key, nonce, plainData, cipherData)
				if err != nil {
					return fmt.Errorf("Encrypting with aes256gcm, got: %w", err)
				}
				nWriten, err := dst.Write(cipherData)
				if err != nil {
					return fmt.Errorf("Writing cipherdata, got: %w",)
				}
				if nWriten != len(cipherData) {
					return fmt.Errorf("Wrote lesser, than needed")
				}
				lastCunkSize = nWriten
			} else {
				nWriten = 0
			}
			chunkPosition++
		}
		return fmt.Errorf("Expected EOF") 
	} else if F.EncryptionFunction == "chacha20poly1305" {
		//TODO:
		return fmt.Errorf("Not ready yet") 
	}
	return fmt.Errorf("Unknown symmetric encryption function :%s", F.EncryptionFunction)
}



func (F FileHeader) DecryptBody(src io.Reader, dst io.Writer, key, salt, nonceSource []byte) {

	if F.EncryptionFunction == "aes256gcm" {
		// TODO: check if boundaries is ok 
		overhead := aes256gcm.GetOverhead(key, plainData)
		plainDataChunkSize := F.ChunkSize - overhead
		// TODO: add check if plainDataCunkSize is positive
		cryptBuff := make([]byte, F.ChunkSize)
		chunkPosition := 0
		var lastChunkSize int
		for x:=0;x<F.ChunksAmount;x++ {
			nRead, err := src.Read(cryptBuff)
			if err == io.EOF {
				// TODO: do we return nil here ?
				return nil
			}
			if err != nil {
				return fmt.Errorf("Reading bytes from reader, got: %w", err)
			}
			nonce := GenerateNonce(x, nonceSource)
			err := aes256gcm.DecryptPtr(key, nonce, cipherData, plainData)
			if err != nil {
				return fmt.Errorf("Decrypting with aes256gcm, got: %w", err)
			}
			nWriten, err := dst.Write(plainData)
			if err != nil {
				return fmt.Errorf("Writing cipherdata, got: %w",)
			}
			if nWriten != len(plainData) {
				return fmt.Errorf("Wrote lesser, than needed")
			}
		}

		for {
			if nRead > 0 {
				lastCunkSize = nWriten
			} else {
				nWriten = 0
			}
			chunkPosition++
		}
		return fmt.Errorf("Expected EOF") 
	} else if F.EncryptionFunction == "chacha20poly1305" {
		//TODO:
		return fmt.Errorf("Not ready yet") 
	}
	return fmt.Errorf("Unknown symmetric encryption function :%s", F.EncryptionFunction)
}


