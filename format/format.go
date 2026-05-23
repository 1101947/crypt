package format

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

type FileHeader struct {
	Magic [4]byte // CRPT
	Version int64 // version as a Timestamp 
	IsValid bool
	IsLittleEndian bool
	EncryptionFunction [16]byte 
	NonceSourceLen uint8
	ChunkSize uint8
	ChunksAmount uint8
	LastChunkSize uint8
	ArgonParams argon2id.Header
}

func (F FileHeader) Verify() error {
	if F.Magic != []byte("CRPT") {
		return fmt.Errorf("Invalid magic number.")
	}
	if !F.IsValid {
		return fmt.Errorf("Format is invalid")
	}
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
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.NonceSourceLen))

	start = end
	end = start + 1
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.ChunkSize))

	start = end
	end = start + 1
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.ChunkAmount))

	start = end
	end = start + 1
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.LastChunkSize))

	start = end
	end = start + 34 
	Argon2id.Encode(F.ArgonParams, start)
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
	f.IsValid = (data[start] & FlagIsValid) != 0
	f.IsLittleEndian = (data[start] & FlagIsLittleEndian) != 0

	start = end
	end = start + len(F.EncryptionFunction) 
	_ = copy(data[start:end], F.EncryptionFunction) 

	start = end
	end = start + 1
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.NonceSourceLen))

	start = end
	end = start + 1
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.ChunkSize))

	start = end
	end = start + 1
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.ChunkAmount))

	start = end
	end = start + 1
	binary.LittleEndian.PutUint8(data[start:end], uint8(F.LastChunkSize))

	start = end
	end = start + 1
	Argon2id.Decode(F.ArgonParams, start)
}

func (F *FileHeader) Read(file *os.File) error {

	err := F.UnmarshalBinary(data []byte) error {

}


func (F FileHeader) Encrypt(src io.Reader, key []byte, dstFile string) error {
//	key, err := secret.GetKey(F.ArgonParams)
//	if err != nil {
//		return fmt.Errorf("Getting key got: %w", err)
//	}
	f, err := os.Create(dstFile)
	if err != nil {
		return fmt.Errorf("Creating file, got: %w", err)
	}
	defer f.Close()

	var header [128]byte
	(*F.FileHeader).Encode(*header)
	f.Write(header)
	if err != nil {
		return err
	}
	if n != len(header) {
		return fmt.Errorf("Number of writen bytes and length of header doesnt match.")
	}

	F.WriteBody(input io.Reader, key []byte)

	n, err := f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("Expected offset to be zero, but got: %d", n)
	}

	(*F.FileHeader).Encode(*header)
	n, err := f.Write(header[:])
	if err != nil {
		return err
	}
	if n != len(header) {
		return fmt.Errorf("Number of writen bytes and length of header doesnt match.")
	}
	return nil
}

func (F FileHeader) WriteBody(src io.Reader, dst *os.File, key, salt, nonceSource []byte) {
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
	if n != len(salt) {
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


