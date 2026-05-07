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
	ArgonParamsLen uint8
	ArgonParams argon2id.Params
	NonceSourceLen uint8
	NonceSource []byte
	EncryptionFunction [16]byte 
	ChunkSize uint8
	ChunksAmount uint8
	LastChunkSize uint8
}

func (F FileHeader) Verify() error {
	if F.Magic != []byte("CRPT") {
		return fmt.Errorf("Invalid magic number.")
	}
	if !F.IsValid {
		return fmt.Errorf("Format is invalid")
	}
}

func (F FileHeader) MarshalBinary() (data []byte, err error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, F.Magic)
	if err != nil {
		return nil, fmt.Errorf("Writing magic, got: %w", err) 
	}
	err := binary.Write(buf, binary.LittleEndian, F.Version)
	if err != nil {
		return nil, fmt.Errorf("Writing version, got: %w", err) 
	}
	err := binary.Write(buf, binary.LittleEndian, F.IsValid)
	if err != nil {
		return nil, fmt.Errorf("Writing validity flag, got: %w", err) 
	}
	err := binary.Write(buf, binary.LittleEndian, F.IsLittleEndian)
	if err != nil {
		return nil, fmt.Errorf("Writing little-endiannes flag, got: %w", err) 
	}
	argonParamsBytes, err := F.ArgonParams.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Marshaling argon params to bytes, got: %w", err) 
	}
	F.ArgonParamsLen = len(argonParamsBytes)
	err := binary.Write(buf, binary.LittleEndian, F.ArgonParamsLen)
	if err != nil {
		return nil, fmt.Errorf("Writing argon params length, got: %w", err) 
	}
	_, err := buf.Write(argonParamsBytes)
	if err != nil {
		return nil, fmt.Errorf("Writing argon params, got: %w", err) 
	}

	err := binary.Write(buf, binary.LittleEndian, F.NonceSourceLen)
	if err != nil {
		return nil, fmt.Errorf("Writing nonce source length, got: %w", err) 
	}
	_, err := buf.Write(F.NonceSource)
	if err != nil {
		return nil, fmt.Errorf("Writing nonce source, got: %w", err) 
	}
	err := binary.Write(buf, binary.LittleEndian, F.EncryptionFunction)
	if err != nil {
		return nil, fmt.Errorf("Writing encryption function, got: %w", err) 
	}
	err := binary.Write(buf, binary.LittleEndian, F.ChunkSize)
	if err != nil {
		return nil, fmt.Errorf("Writing chunk size, got: %w", err) 
	}
	err := binary.Write(buf, binary.LittleEndian, F.ChunkAmount)
	if err != nil {
		return nil, fmt.Errorf("Writing chunk amount, got: %w", err) 
	}
	err := binary.Write(buf, binary.LittleEndian, F.LastChunkSize)
	if err != nil {
		return nil, fmt.Errorf("Writing last chunk size, got: %w", err) 
	}
	return buf.Bytes(), nil
}

func (F FileHeader) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.LittleEndian, F.Magic)
	if err != nil {
		return fmt.Errorf("Reading magic number, got: %w", err)
	}
	// TODO: add test for correct magick
	err := binary.Read(reader, binary.LittleEndian, F.Version)
	if err != nil {
		return fmt.Errorf("Reading version, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, F.IsValid)
	if err != nil {
		return fmt.Errorf("Reading validity flag, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, F.IsLittleEndian)
	if err != nil {
		return fmt.Errorf("Reading little-endiannes flag, got: %w", err)
	}

	err := binary.Read(reader, binary.LittleEndian, F.ArgonParamsLength)
	if err != nil {
		return fmt.Errorf("Reading argon params length, got: %w", err)
	}
	argonBytes := make([]byte, F.ArgonParamsLength)
	_, err := io.ReadFull(reader, argonBytes)
	if err != nil {
		return fmt.Errorf("Reading argon params, got: %w", err)
	}
	err := F.ArgonParams.UnmarshalBinary(argonBytes)
	if err != nil {
		return fmt.Errorf("Unmarshalling argon from bytes, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, F.NonceSourceLen)
	if err != nil {
		return fmt.Errorf("Reading nonce source len, got: %w", err)
	}
	F.NonceSource := make([]byte, F.NonceSourceLen)
	_, err := io.ReadFull(reader, F.NonceSource)
	if err != nil {
		return fmt.Errorf("Reading nonce source, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, F.EncryptionFunction)
	if err != nil {
		return fmt.Errorf("Reading encryption function, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, F.ChunkSize)
	if err != nil {
		return fmt.Errorf("Reading chunk size, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, F.ChunksAmount)
	if err != nil {
		return fmt.Errorf("Reading chunks amount, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, F.LastChunkSize)
	if err != nil {
		return fmt.Errorf("Reading chunks amount, got: %w", err)
	}
	return nil
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
				headerBytes, err := F.MarshalBinary()
				if err != nil {
					return fmt.Errorf("Marshaling header to bytes, got: %w", err)
				}
				n, err := outputFl.WriteAt(headerBytes, 0)
				if err != nil {
					return err
				}
				if n != HeaderSize {
					return fmt.Errorf("Wrote too many or too little bytes of header.")
				}
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

