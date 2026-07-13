package argon2id 

import (
	"fmt"
	"encoding/binary"

	//"crypto/rand"
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

type Header struct {
	Version int64  
	Iterations uint32
	Memory uint32
	KeyLength uint32
	SaltLength uint32
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
	end = start + 4
	binary.LittleEndian.PutUint32(data[start:end], H.SaltLength)

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
	end = start + 4
	H.SaltLength = binary.LittleEndian.Uint32(data[start:end])

	start = end
	end = start + 2 
	H.Parallelism = uint8(binary.LittleEndian.Uint16(data[start:end]))
} 



//
//func (P *Params) MarshalBinary() (data []byte, err error) {
//	buf := new(bytes.Buffer)
//	err := binary.Write(buf, binary.LittleEndian, P.Version)
//	if err != nil {
//		return nil, fmt.Errorf("Writing version to bytes, got: %w", err)
//	}
//	err := binary.Write(buf, binary.LittleEndian, P.SaltLength)
//	if err != nil {
//		return nil, fmt.Errorf("Writing salt lenght to bytes, got: %w", err)
//	}
//	_, err := buf.Write(Salt)
//	if err != nil {
//		return nil, fmt.Errorf("Writing salt, got: %w", err)
//	}
//	err := binary.Write(buf, binary.LittleEndian, P.Iterations)
//	if err != nil {
//		return nil, fmt.Errorf("Writing iterations, got: %w", err)
//	}
//	err := binary.Write(buf, binary.LittleEndian, P.Memory)
//	if err != nil {
//		return nil, fmt.Errorf("Writing memory, got: %w", err)
//	}
//	err := binary.Write(buf, binary.LittleEndian, P.Parallelism)
//	if err != nil {
//		return nil, fmt.Errorf("Writing parallelism, got: %w", err)
//	}
//	err := binary.Write(buf, binary.LittleEndian, P.KeyLength)
//	if err != nil {
//		return nil, fmt.Errorf("Writing keylength, got: %w", err)
//	}
//	return buf.Bytes(), nil
//}
//
//func (P *Params) UnmarshalBinary(data []byte) error (
//	reader := bytes.NewReader(data)
//	err := binary.Read(reader, binary.LittleEndian, P.Version)
//	if err != nil {
//		return nil, fmt.Errorf("Reading version, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, P.SaltLength)
//	if err != nil {
//		return nil, fmt.Errorf("Reading salt length, got: %w", err)
//	}
//	R.Salt := make([]byte, P.SaltLength)
//	_, err := io.ReadFull(reader, data) 
//	if err != nil {
//		return nil, fmt.Errorf("Reading salt, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, P.Iterations)
//	if err != nil {
//		return nil, fmt.Errorf("Reading iterations, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, P.Memory)
//	if err != nil {
//		return nil, fmt.Errorf("Reading memory, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, P.Parallelism)
//	if err != nil {
//		return nil, fmt.Errorf("Reading Parallelism, got: %w", err)
//	}
//	err := binary.Read(reader, binary.LittleEndian, P.KeyLength)
//	if err != nil {
//		return nil, fmt.Errorf("Reading key length, got: %w", err)
//	}
//	return nil
//)

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
