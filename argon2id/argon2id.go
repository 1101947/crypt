package argon2id 

import (
	"fmt"
	"encoding/binary"

	"crypto/rand"
	"golang.org/x/crypto/argon2"
)


type Params struct {
	Header Header
	Salt []byte
}

func GetDefaultHeader() Header {
	return Header{
		Version: 0,
		Iterations: 1,
		Memory: 2*1024*1024,
		KeyLength: 32,
		SaltLength: 16,
		Parallelism: 4,
	}
}

func GetDefaultHeaderLessMemory() Header {
	return Header{
		Version: 0,
		Iterations: 3,
		Memory: 64*1024,
		KeyLength: 32,
		SaltLength: 16,
		Parallelism: 4,
	}
}


const HeaderSize = 28

// Most fields of this struct may be set by user
type Header struct {
	Version int64 // should not be set bu user 
	Iterations uint32
	Memory uint32
	KeyLength uint32 // should not be set by user
	SaltLength uint16
	Parallelism uint8
}

func Compare(h1, h2 Header) string {
	s := ""
	if h1.Version != h2.Version {
		s += " Version "
	}
	if h1.Iterations != h2.Iterations {
		s += " Iterations " 
	}
	if h1.Memory != h2.Memory  {
		s += " Memory " 
	}
	if h1.KeyLength != h2.KeyLength  {
		s += " KeyLength " 
	}
	if h1.SaltLength != h2.SaltLength  {
		s += " SaltLength " 
	}

	if h1.Parallelism != h2.Parallelism  {
		s += " Parallelism " 
	}
	return s
}

func (H *Header) Encode(data *[128]byte) {
     	// TODO: check valid start
     	//start := 37
     	start := 56 
	end := start + 8
	binary.LittleEndian.PutUint64(data[start:end], uint64(H.Version))

	start = end
	end = start + 4
	binary.LittleEndian.PutUint32(data[start:end], H.Iterations)

	start = end
	end = start + 4
	binary.LittleEndian.PutUint32(data[start:end], H.Memory)

	start = end
	end = start + 4
	binary.LittleEndian.PutUint32(data[start:end], H.KeyLength)

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], H.SaltLength)

	start = end
	end = start + 2 
	binary.LittleEndian.PutUint16(data[start:end], uint16(H.Parallelism))
} 

func (H *Header) Decode(data *[128]byte) {
     	// TODO: check valid start
	// start := 58
     	start := 56
	end := start + 8
	H.Version = int64(binary.LittleEndian.Uint64(data[start:end]))

	start = end
	end = start + 4
	H.Iterations = binary.LittleEndian.Uint32(data[start:end])

	start = end
	end = start + 4
	H.Memory = binary.LittleEndian.Uint32(data[start:end])

	start = end
	end = start + 4
	H.KeyLength = binary.LittleEndian.Uint32(data[start:end])

	start = end
	end = start + 2 
	H.SaltLength = binary.LittleEndian.Uint16(data[start:end])

	start = end
	end = start + 2 
	H.Parallelism = uint8(binary.LittleEndian.Uint16(data[start:end]))
} 


func (P Params) Hash(key []byte) ([]byte, error) {
//	if len(key) != int(P.KeyLength) {
//		return nil, fmt.Errorf("Provided key length: %d differs from the one stated in params: %d ", len(key), P.KeyLength)
//	}
	if len(P.Salt) != int(P.Header.SaltLength) {
		return nil, fmt.Errorf("Provided salt length: %d differs from the one stated in params: %d ", len(P.Salt), P.Header.SaltLength)
	}
	hashKey := argon2.IDKey(key, P.Salt, P.Header.Iterations, P.Header.Memory, P.Header.Parallelism, P.Header.KeyLength)
	return hashKey, nil
}

func GetSalt(saltLen uint16) ([]byte, error) {
	key := make([]byte, int(saltLen))
	i, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("Reading random bytes, got: %w", err)
	}
	if i != int(saltLen) {
		return nil, fmt.Errorf("Read wrong number of bytes. Must have been read %d bytes , but read %d bytes.", saltLen, i)
	}
	return key, nil
}
