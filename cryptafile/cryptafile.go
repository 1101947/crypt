package cryptafile 
//
import (
	"io"
	"os"
	"fmt"
	"crypto/rand"
	"crypt/argon2id"
	"crypt/aes256gcm"
	"crypt/chacha20poly1305"
	"crypt/header"
	"crypt/cryptochunk"
//	"math"
//	"strconv"
//	"golang.org/x/term"
//	"github.com/1101947/cliargumentrouter/flag"
)

func NewCryptData() CryptData {
	C := CryptData{
		H: header.GetDefaultHeader(),
		Cr: cryptochunk.CryptChunk{},
		Salt: nil,
		KeyGetter: nil,
		In: nil, 
		Out: nil,
	}
	return C 
} 

type CryptData struct {
	H header.FileHeader
	Cr cryptochunk.CryptChunk
	Salt []byte
	KeyGetter keyGetter 
	In, Out *os.File
}

type keyGetter interface {
	GetKey(argon2id.Params) ([]byte, error)
}

func (C CryptData) Encrypt() error {
	//argonHeader := argon2id.GetDefaultHeader()
	argonHeader := C.H.ArgonParams
	salt, err := argon2id.GetSalt(argonHeader.SaltLength)
	if err != nil {
		return fmt.Errorf("Generating salt for argon2id function, got: %w", err)
	}
	argonParams := argon2id.Params{
		Header: argonHeader,
		Salt: salt,
	}
	fmt.Println("DEBUG: keygetter: ", C.KeyGetter)
	key, err  := C.KeyGetter.GetKey(argonParams)
	if err != nil {
		return fmt.Errorf("Geting key from user, got: %w", err)
	}
	// TODO: select crypter based on header.cryptofunc

	cryptoFuncName := string(C.H.EncryptionFunction[:])
	if cryptoFuncName[:9] == "aes256gcm" {
		C.Cr.Crypter = aes256gcm.GetAES256GCM()
	} else if cryptoFuncName == "chacha20poly1305" {
		C.Cr.Crypter = chacha20poly1305.GetChaCha20Poly1305()
	} else {
		return fmt.Errorf("Ivalid encryption function option in header: %s", cryptoFuncName)
	}

	overhead, err := C.Cr.Crypter.GetOverhead(key)

	if err != nil {
		return fmt.Errorf("Getting overhead, got: %w", err)
	}
	C.H.Overhead = overhead 

	nonceSourceLen, err := C.Cr.Crypter.GetNonceSize(key)
	if err != nil {
		return fmt.Errorf("Getting nonce source size, got: %w", err)
	}
	C.H.NonceSourceLen = nonceSourceLen
	nonceSource := make([]byte, nonceSourceLen)
	nonceSourceBytesRead, err := rand.Read(nonceSource)
	if err != nil {
		return fmt.Errorf("Reading random bytes into nonceSource buffer, got: %w", err)
	}
	if nonceSourceBytesRead != int(nonceSourceLen) {
		return fmt.Errorf("Reading random bytes into nonceSource buffer: number of bytes should be equal to nonceSourceLen: %d, but is: %d", nonceSourceLen, nonceSourceBytesRead)
	}
	plainDataChunkSize := C.H.ChunkSize - overhead 
	plainBuf := make([]byte, int(plainDataChunkSize))
	C = CryptData{
		H: C.H,
		Cr: cryptochunk.CryptChunk{
			In: plainBuf,
			Out: make([]byte, C.H.ChunkSize),
			Key: key,
			NonceSource: nonceSource,
			ChunkPosition: 0,
			Crypter: C.Cr.Crypter,
		},
		Salt: salt,
		KeyGetter: C.KeyGetter,
		In: C.In,
		Out: C.Out,
	}

	err = C.H.Verify()
	if !header.IsSetToInvalidHeader(err) {
		if err == nil {
			return fmt.Errorf("Verifying header before the encryption. Header must be set to invalid before encrypting.")
		}
		return fmt.Errorf("Verifying header before the encryption, got: %w", err)
	}
	var headerBuf [128]byte 
	C.H.Encode(&headerBuf)
	headerBytesWriten, err := (C.Out).Write(headerBuf[:])
	if err != nil {
		return fmt.Errorf("Trying to write header buffer to file, got: %w", err)
	}
	if headerBytesWriten != len(headerBuf) {
		return fmt.Errorf("Number of bytes writen differs from the amount of bytes in headerBuf(128)")
	}
	saltBytesWriten, err := C.Out.Write(C.Salt)
	if err != nil {
		return fmt.Errorf("Trying to write salt buffer to file, got: %w", err)
	}
	if saltBytesWriten != len(C.Salt) {
		return fmt.Errorf("Number of bytes writen: %d differs from the amount of bytes in C.Salt: %d", saltBytesWriten, len(C.Salt))
	}
	nonceBytesWriten, err := C.Out.Write(C.Cr.NonceSource)
	if err != nil {
		return fmt.Errorf("Trying to write nonce source buffer to file, got: %w", err)
	}
	if nonceBytesWriten != len(C.Cr.NonceSource) {
		return fmt.Errorf("Number of bytes writen: %d differs from the amount of bytes in C.Cr.NonceSource: %d", nonceBytesWriten, len(C.Cr.NonceSource))
	}
	fmt.Printf("DEBUG: noncesourcelen: %d , saltlen: %d\n", len(C.Cr.NonceSource), len(C.Salt))

	// cryptBuf and plainBuf are just cr.Out and cr.In
	// TODO:
	// their making should be done in handler, not here
	var chunksAmount uint16
	chunksAmount = uint16(0)
	var lastChunkSize uint16
	var readIntoPlain int
	var writeToOut int

	fmt.Println("DEBUG: Hiiiiii")
	fmt.Printf("DEBUG: header: %v cryptochunk: %v \n", C.H, C.Cr)
	for {
		readIntoPlain, err = io.ReadFull(C.In, C.Cr.In)
		if err == io.ErrUnexpectedEOF {
			fmt.Printf("DEBUG: unexpected EOF, chunks amount: %d\n", chunksAmount)
			break
		}
		if err == io.EOF {
			fmt.Printf("DEBUG: EOF, chunks amount: %d , C.In: %v , C.Cr.In: %v \n", chunksAmount, C.In, C.Cr.In)
			break
		}
		if err != nil {
			return fmt.Errorf("Trying to read bytes from file into buffer, got: %w", err)
		}
		if readIntoPlain <= 0 {
			return fmt.Errorf("Have read invalid number of bytes: %d", readIntoPlain)
		} 
		chunksAmount++
		C.Cr.ChunkPosition = chunksAmount 
		err = C.Cr.Encrypt()
		if err != nil {
			return fmt.Errorf("Encrypting, got: %w", err)
		}
		writeToOut, err = C.Out.Write(C.Cr.Out)
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(C.Cr.Out) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	if readIntoPlain < 0 {
		return fmt.Errorf("Invalid number of bytes read from file: negative: %d", readIntoPlain)
	}
	lastChunkSize = 0
	if readIntoPlain > 0 {
		lastChunkSize = uint16(readIntoPlain) + C.H.Overhead 
		C.Cr.ChunkPosition = chunksAmount + 1
		err = C.Cr.Encrypt()
		if err != nil {
			return fmt.Errorf("Encrypting last chunk, got: %w", err)
		}
		writeToOut, err = C.Out.Write(C.Cr.Out)
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(C.Cr.Out) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	offset, err := C.Out.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("Seeking for the start of the file to rewrite the header, got: %w", err)
	}
	if offset != 0 {
		return fmt.Errorf("Expected offset to be zero, but got: %d", offset)
	}
	C.H.ChunksAmount = chunksAmount
	C.H.LastChunkSize = lastChunkSize
	C.H.IsValid = true
	C.H.Encode(&headerBuf)
	err = C.H.Verify()
	if err != nil {
		return fmt.Errorf("Verifying header after encryption, got: %w", err)
	}
	headerBytesWriten, err = C.Out.Write(headerBuf[:])
	if err != nil {
		return fmt.Errorf("Trying to write header buffer to file, got: %w", err)
	}
	if headerBytesWriten != len(headerBuf) {
		return fmt.Errorf("Number of bytes writen differs from the amount of bytes in headerBuf(128)")
	}
	return nil
}

func (C CryptData) Decrypt() error {
	var headerBuf [128]byte 
	readIntoHeaderBuf, err := C.In.Read(headerBuf[:])
	if err != nil {
		return fmt.Errorf("Reading header from file to buffer, got: %w", err)
	}
	if readIntoHeaderBuf != len(headerBuf) {
		// TODO: have been read typo ?
		return fmt.Errorf("Read wrong number of bytes to header. Must have been read %d bytes, but actualy read %d .", len(headerBuf), readIntoHeaderBuf)
	}
	C.H.Decode(&headerBuf)
	err = C.H.Verify()
	if err != nil {
		return fmt.Errorf("Verifying header, got: %w", err)
	} 
	saltBuff := make([]byte, int(C.H.ArgonParams.SaltLength)) 
	readIntoSaltBuff, err := C.In.Read(saltBuff)
	if err != nil {
		return fmt.Errorf("Reading salt from file to buffer, got: %w", err)
	}
	if readIntoSaltBuff != int(C.H.ArgonParams.SaltLength) {
		return fmt.Errorf("Read wrong number of bytes. Must have been read %d bytes, but actualy read %d .", C.H.ArgonParams.SaltLength, readIntoSaltBuff)
	}

	argonParams := argon2id.Params{
		Header: C.H.ArgonParams,
		Salt: saltBuff,
	}
	key, err  := C.KeyGetter.GetKey(argonParams)
	if err != nil {
		return fmt.Errorf("Geting key from user, got: %w", err)
	}

	nonceSource := make([]byte, C.H.NonceSourceLen)
	readIntoNonceSourceBuff, err := C.In.Read(nonceSource)
	if err != nil {
		return fmt.Errorf("Reading nonce source from file to buffer, got: %w", err)
	}
	if readIntoNonceSourceBuff != int(C.H.NonceSourceLen) {
		return fmt.Errorf("Read wrong number of bytes. Must have been read %d bytes, but actualy read %d .", C.H.NonceSourceLen, readIntoNonceSourceBuff)
	}
	C.Cr.NonceSource = nonceSource
	cryptoFuncName := string(C.H.EncryptionFunction[:])
	if cryptoFuncName[:9] == "aes256gcm" {
		C.Cr.Crypter = aes256gcm.GetAES256GCM()
	} else if cryptoFuncName == "chacha20poly1305" {
		C.Cr.Crypter = chacha20poly1305.GetChaCha20Poly1305()
	} else {
		return fmt.Errorf("Ivalid encryption function option in header: %s", cryptoFuncName)
	}

	overhead, err := C.Cr.Crypter.GetOverhead(key)
	if err != nil {
		return fmt.Errorf("Getting overhead, got: %w", err)
	}
	plainDataChunkSize := C.H.ChunkSize - overhead 
	plainBuf := make([]byte, plainDataChunkSize)

	// Its a little bit strange that i redefine c here, maybe redesign
	C = CryptData{
		H: C.H,
		Cr: cryptochunk.CryptChunk{
			In: make([]byte, C.H.ChunkSize),
			Out: plainBuf,
			Key: key,
			NonceSource: nonceSource,
			ChunkPosition: 0,
			Crypter: C.Cr.Crypter,
		},
		Salt: saltBuff,
		KeyGetter: C.KeyGetter,
		In: C.In,
		Out: C.Out,
	}

//	// What about comparison with C.H.NonceSourceLen ?
//	if readNonceSource != len(C.Cr.NonceSource) {
//		return fmt.Errorf("Number of nonce source bytes read from file: %d differ from length of nonce source buffer: %d", readNonceSource, len(C.Cr.NonceSource))
//	}
	var readIntoCrypt int
	var readIntoPlain int
	var writeToOut int
	var chunksPos int
	chunksAmount := int(C.H.ChunksAmount)
	for chunksPos=1;chunksPos<=chunksAmount;chunksPos++ {
		readIntoCrypt, err = C.In.Read(C.Cr.In)
		// TODO: maybe remove ?
		if err == io.EOF && readIntoPlain == 0 {

		}
		if err != nil {
			return fmt.Errorf("Trying to read bytes from file into buffer, got: %w", err)
		}
		if readIntoCrypt <= 0 {
			return fmt.Errorf("Have read invalid number of bytes")
		} 

		C.Cr.ChunkPosition = uint16(chunksPos)
		err = C.Cr.Decrypt()
		if err != nil {
			return fmt.Errorf("Decrypting, got: %w", err)
		}
		writeToOut, err = C.Out.Write(C.Cr.Out)
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(C.Cr.Out) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	if C.H.LastChunkSize != 0 {
		readIntoCrypt, err = C.In.Read(C.Cr.In)
		if err != nil && err != io.EOF {
			return fmt.Errorf("Trying to read bytes from file into buffer, got: %w", err)
		}
		if readIntoCrypt <= 0 {
			return fmt.Errorf("Have read invalid number of bytes")
		} 
		C.Cr.ChunkPosition = C.Cr.ChunkPosition + 1
		err = C.Cr.Decrypt()
		if err != nil {
			return fmt.Errorf("Decrypting, got: %w", err)
		}
		realData := (C.H.LastChunkSize - C.H.Overhead)
		writeToOut, err = C.Out.Write(C.Cr.Out[:realData])
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(C.Cr.Out[:realData]) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	return nil
}
