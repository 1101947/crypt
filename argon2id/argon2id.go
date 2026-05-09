package argon2id 

import (
	"fmt"

	//"crypto/rand"
	"golang.org/x/crypto/argon2"
)

type Params struct {
	Header Header
	Salt []byte
}

type Header struct {
	Version int64  
	Iterations uint32
	Memory uint32
	Parallelism uint8
	KeyLength uint32
	SaltLength uint32
}

func (P *Params) MarshalBinary() (data []byte, err error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, P.Version)
	if err != nil {
		return nil, fmt.Errorf("Writing version to bytes, got: %w", err)
	}
	err := binary.Write(buf, binary.LittleEndian, P.SaltLength)
	if err != nil {
		return nil, fmt.Errorf("Writing salt lenght to bytes, got: %w", err)
	}
	_, err := buf.Write(Salt)
	if err != nil {
		return nil, fmt.Errorf("Writing salt, got: %w", err)
	}
	err := binary.Write(buf, binary.LittleEndian, P.Iterations)
	if err != nil {
		return nil, fmt.Errorf("Writing iterations, got: %w", err)
	}
	err := binary.Write(buf, binary.LittleEndian, P.Memory)
	if err != nil {
		return nil, fmt.Errorf("Writing memory, got: %w", err)
	}
	err := binary.Write(buf, binary.LittleEndian, P.Parallelism)
	if err != nil {
		return nil, fmt.Errorf("Writing parallelism, got: %w", err)
	}
	err := binary.Write(buf, binary.LittleEndian, P.KeyLength)
	if err != nil {
		return nil, fmt.Errorf("Writing keylength, got: %w", err)
	}
	return buf.Bytes(), nil
}

func (P *Params) UnmarshalBinary(data []byte) error (
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.LittleEndian, P.Version)
	if err != nil {
		return nil, fmt.Errorf("Reading version, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, P.SaltLength)
	if err != nil {
		return nil, fmt.Errorf("Reading salt length, got: %w", err)
	}
	R.Salt := make([]byte, P.SaltLength)
	_, err := io.ReadFull(reader, data) 
	if err != nil {
		return nil, fmt.Errorf("Reading salt, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, P.Iterations)
	if err != nil {
		return nil, fmt.Errorf("Reading iterations, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, P.Memory)
	if err != nil {
		return nil, fmt.Errorf("Reading memory, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, P.Parallelism)
	if err != nil {
		return nil, fmt.Errorf("Reading Parallelism, got: %w", err)
	}
	err := binary.Read(reader, binary.LittleEndian, P.KeyLength)
	if err != nil {
		return nil, fmt.Errorf("Reading key length, got: %w", err)
	}
	return nil
)

func (P Params) Hash(key []byte) ([]byte, error) {
//	if len(key) != int(P.KeyLength) {
//		return nil, fmt.Errorf("Provided key length: %d differs from the one stated in params: %d ", len(key), P.KeyLength)
//	}
	if len(P.Salt) != int(P.SaltLength) {
		return nil, fmt.Errorf("Provided salt length: %d differs from the one stated in params: %d ", len(P.Salt), P.SaltLength)
	}
	hashKey := argon2.IDKey(key, P.Salt, P.Iterations, P.Memory, P.Parallelism, P.KeyLength)
	return hashKey, nil
}
