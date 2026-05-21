package format

// Steam for streaming - each chunk have length field.
// type Stream struct {}

// File for storing encrypted data as files. Chunk size, amount of chunks, size of lenght chunk(1 < size of last chunk < chunk size) specified in header.
// type File struct {}

// Escaped - not shure if it have any usecase, mabe for storing in popular serialization formats like json, yaml
// type Escaped


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

//
//func (F FileHeader) UnmarshalBinary(data []byte) error {
//	reader := bytes.NewReader(data)
//	err := binary.Read(reader, binary.LittleEndian, F.Magic)
//	if err != nil {
//		return fmt.Errorf("Reading magic number, got: %w", err)
//	}
//	// TODO: add test for correct magick
//	err := binary.Read(reader, binary.LittleEndian, F.Version)
//	if err != nil {
//		return fmt.Errorf("Reading version, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, F.IsValid)
//	if err != nil {
//		return fmt.Errorf("Reading validity flag, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, F.IsLittleEndian)
//	if err != nil {
//		return fmt.Errorf("Reading little-endiannes flag, got: %w", err)
//	}
//
//	err := binary.Read(reader, binary.LittleEndian, F.ArgonParamsLength)
//	if err != nil {
//		return fmt.Errorf("Reading argon params length, got: %w", err)
//	}
//	argonBytes := make([]byte, F.ArgonParamsLength)
//	_, err := io.ReadFull(reader, argonBytes)
//	if err != nil {
//		return fmt.Errorf("Reading argon params, got: %w", err)
//	}
//	err := F.ArgonParams.UnmarshalBinary(argonBytes)
//	if err != nil {
//		return fmt.Errorf("Unmarshalling argon from bytes, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, F.NonceSourceLen)
//	if err != nil {
//		return fmt.Errorf("Reading nonce source len, got: %w", err)
//	}
//	F.NonceSource := make([]byte, F.NonceSourceLen)
//	_, err := io.ReadFull(reader, F.NonceSource)
//	if err != nil {
//		return fmt.Errorf("Reading nonce source, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, F.EncryptionFunction)
//	if err != nil {
//		return fmt.Errorf("Reading encryption function, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, F.ChunkSize)
//	if err != nil {
//		return fmt.Errorf("Reading chunk size, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, F.ChunksAmount)
//	if err != nil {
//		return fmt.Errorf("Reading chunks amount, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, F.LastChunkSize)
//	if err != nil {
//		return fmt.Errorf("Reading chunks amount, got: %w", err)
//	}
//	return nil
//}
//
//func (F FileHeader) Write(file *os.File) error {
//	headerBytes, err := F.MarshalBinary()
//	if err != nil {
//		return fmt.Errorf("Marshaling header to bytes, got: %w", err)
//	}
//	n, err := file.WriteAt(headerBytes, 0)
//	if err != nil {
//		return err
//	}
//	if n != HeaderSize {
//		return fmt.Errorf("Wrote too many or too little bytes of header.")
//	}
//	return nil
//}

func (F *FileHeader) Read(file *os.File) error {

	err := F.UnmarshalBinary(data []byte) error {

}


func (F FileHeader) Encrypt(input io.Reader, output string) error {
	key, err := secret.GetKey(F.ArgonParams)
	if err != nil {
		return fmt.Errorf("Getting key got: %w", err)
	}
	if F.EncryptionFunction == "aes256gcm" {
		// TODO: check if boundaries is ok 
		overhead := aes256gcm.GetOverhead(key, plainData)
		plainDataChunkSize := F.ChunkSize - overhead
		plainData := make([]byte, plainDataChunkSize)
		chunkPosition := 0
		var lastChunkSize int
		outputFl, err := os.Create(output)
		if err != nil {
			return err
		}
		for {
			nRead, err := input.Read(plainData)
			if err == io.EOF {
				F.ChunksAmount = chunkPosition
				F.LastChunkSize = lastChunkSize
				return nil
			}
			if err != nil {
				return fmt.Errorf("Reading bytes from reader, got: %w", err)
			}
			if nRead > 0 {
				nonce := GenerateNonce(chunkPosition, F.NonceSource)
				err := aes256gcm.EncryptPtr(key, nonce, plainData, cipherData)
				if err != nil {
					return fmt.Errorf("Encrypting with aes256gcm, got: %w", err)
				}
	
				nWriten, err := outputWR.Write(cipherData)
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


func (F FileHeader) Encrypt(input io.Reader, output string) error {

}
