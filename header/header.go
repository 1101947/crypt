package header

import (
       "encoding/binary"
       "crypt/argon2id"
)

const Magic = "CRPT" 
const Version = 0
const HeaderSize int = 128

func GetDefaultHeader() FileHeader {
	argonHeader := argon2id.GetDefaultHeader()
	header := FileHeader{
		Magic: [4]byte([]byte(Magic)),
		Version: int64(Version),
		IsValid: false, 
		IsLittleEndian: true,
		EncryptionFunction: [16]byte{},
		NonceSourceLen: 0, // TODO  
		ChunkSize: 1024, // TODO 
		ChunksAmount: 0, // TODO 
		LastChunkSize: 0, // TODO 
		ArgonParams: argonHeader,
	}
	encfunc := "aes256gcm"
	_ = copy(header.EncryptionFunction[:], encfunc) 
	return header
}
// using uint16 as maximum capacity uint to make it trivial(is this the right word?) to convert to int on both 32bit and 64bit platforms
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
	Overhead uint16
	// TODO: rename to ArgonHeader
	ArgonParams argon2id.Header
}

func Compare(h1, h2 FileHeader) string {
	s := ""
	h1Magic := string(h1.Magic[:])
	h2Magic := string(h2.Magic[:])
	if h1Magic != h2Magic {
		s += " Magic "
	}
	if h1.Version != h2.Version {
		s += "Version "
	} 
	if h1.IsValid != h2.IsValid {
		s += "IsValid "
	}
	if h1.IsLittleEndian != h2.IsLittleEndian {
		s += "IsLittleEndian "
	}
	h1Encfunc := string(h1.EncryptionFunction[:])
	h2Encfunc := string(h2.EncryptionFunction[:])
	if h1Encfunc != h2Encfunc {
		s += " EncryptionFunction "
	}
	if h1.NonceSourceLen != h2.NonceSourceLen {
		s += "NonceSourceLen "
	}
	if h1.ChunkSize != h2.ChunkSize  {
		s += "ChunkSize "
	}
	if h1.ChunksAmount != h2.ChunksAmount  {
		s += "ChunksAmount "
	}
	if h1.LastChunkSize != h2.LastChunkSize  {
		s += "LastChunkSize "
	}
	if h1.Overhead != h2.Overhead {
		s += " Overhead "
	}
	argonCmpString := argon2id.Compare(h1.ArgonParams, h2.ArgonParams)
	if argonCmpString != "" {
		s = s + " Argon2id Start : " + argonCmpString + " :Argon2id End "
	}
	return s
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
	end = start + 2 
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
	binary.LittleEndian.PutUint16(data[start:end], uint16(F.Overhead))

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
	end = start + 2 
	F.NonceSourceLen = binary.LittleEndian.Uint16(data[start:end])

	start = end
	end = start + 2 
	F.ChunkSize = binary.LittleEndian.Uint16(data[start:end])

	start = end
	end = start + 2 
	F.ChunksAmount = binary.LittleEndian.Uint16(data[start:end])

	start = end
	end = start + 2 
	F.LastChunkSize = binary.LittleEndian.Uint16(data[start:end])

	start = end
	end = start + 2 
	F.Overhead = binary.LittleEndian.Uint16(data[start:end])

	start = end
	end = start + 2 
	(F.ArgonParams).Decode(data)
}

