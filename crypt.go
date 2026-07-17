package main
//
import (
	"io"
	"os"
	"fmt"
	"crypto/rand"
	"crypt/argon2id"
	"crypt/aes256gcm"
	"crypt/header"
	"crypt/cryptochunk"
	"golang.org/x/term"
	"github.com/1101947/cliargumentrouter/flag"
)

type CryptHandler struct {
	cryptData cryptData
	interactive string
}

type EncryptHandler CryptHandler

func NewEncryptHandler() EncryptHandler {
	c := NewCryptData()
	return EncryptHandler{
		cryptData: c,
		interactive: "false",
	}
}

type DecryptHandler CryptHandler

func NewDecryptHandler() DecryptHandler {
	c := NewCryptData()
	return DecryptHandler{
		cryptData: c,
		interactive: "false",
	}
}


func (E EncryptHandler) Process(posargs []string) error {
	// TODO: maybe put flags inside EncryptionHandler ?
	flags := flag.DefaultFlags("--", "=", posargs)
	err := flags.Parse()
	if err != nil {
		return fmt.Errorf("Parsing cli arguments, got: %w", err)
	}
	kwargs, posargs := flags.Extract()
	inputVals, ok := kwargs["input"]
	if !ok {
		return fmt.Errorf("Input argument must be specified.")
	}
	if len(inputVals) != 1 {
		return fmt.Errorf("Only one input argument must be specified.")
	}
	var input string
	for _, v := range inputVals {
		input = v
		break
	}
	// TODO: should i add some verification os.Stat(); !os.IsNotExist(), file.IsDir() ?
	inputRD, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("Trying to open file, got : %w", err)
	}
	defer inputRD.Close()

	outputVals, ok := kwargs["output"]
	if !ok {
		return fmt.Errorf("Output argument must be specified.")
	}
	if len(outputVals) != 1 {
		return fmt.Errorf("Only one output argument must be specified.")
	}
	var output string
	for _, v := range outputVals {
		output = v
		break
	}
	outputWR, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("Trying to create file, got : %w", err)
	}
	defer outputWR.Close()

	argonHeader := argon2id.GetDefaultHeader()
	salt, err := argon2id.GetSalt(argonHeader.SaltLength)
	if err != nil {
		return fmt.Errorf("Generating salt for argon2id function, got: %w", err)
	}
	argonParams := argon2id.Params{
		Header: argonHeader,
		Salt: salt,
	}
	// Do get key realy need argonParams as a param ?
	key, err  := GetKey(argonParams)
	if err != nil {
		return fmt.Errorf("Geting key from user, got: %w", err)
	}
	headr := header.GetDefaultHeader()

	crypter := aes256gcm.GetAES256GCM()

	overhead, err := crypter.GetOverhead(key)
	if err != nil {
		return fmt.Errorf("Getting overhead, got: %w", err)
	}
	headr.Overhead = overhead 

	nonceSourceLen, err := crypter.GetNonceSize(key)
	if err != nil {
		return fmt.Errorf("Getting nonce source size, got: %w", err)
	}
	headr.NonceSourceLen = nonceSourceLen
	nonceSource := make([]byte, nonceSourceLen)

	_, err = rand.Read(nonceSource)
	if err != nil {
		return fmt.Errorf("Reading random bytes into nonceSource buffer, got: %w", err)
	}

	// isnt chunksize zero now and needs to be set ?
	plainDataChunkSize := headr.ChunkSize - overhead 
	plainBuf := make([]byte, int(plainDataChunkSize))

	c := cryptData{
		h: headr,
		cr: cryptochunk.CryptChunk{
			In: plainBuf,
			Out: make([]byte, headr.ChunkSize),
			Key: key,
			NonceSource: nonceSource,
			ChunkPosition: 0,
			Crypter: crypter,
		},
		salt: salt,
		in: inputRD,
		out: outputWR,
	}
	err = c.Encrypt()
	return err 
}

func (D DecryptHandler) Process(posargs []string) error {
	// TODO: maybe put flags inside EncryptionHandler ?
	flags := flag.DefaultFlags("--", "=", posargs)
	err := flags.Parse()
	if err != nil {
		return fmt.Errorf("Parsing cli arguments, got: %w", err)
	}
	kwargs, posargs := flags.Extract()
	inputVals, ok := kwargs["input"]
	if !ok {
		return fmt.Errorf("Input argument must be specified.")
	}
	if len(inputVals) != 1 {
		return fmt.Errorf("Only one input argument must be specified.")
	}
	var input string
	for _, v := range inputVals {
		input = v
		break
	}
	// TODO: should i add some verification os.Stat(); !os.IsNotExist(), file.IsDir() ?
	inputRD, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("Trying to open file, got : %w", err)
	}
	defer inputRD.Close()

	outputVals, ok := kwargs["output"]
	if !ok {
		return fmt.Errorf("Output argument must be specified.")
	}
	if len(outputVals) != 1 {
		return fmt.Errorf("Only one output argument must be specified.")
	}
	var output string
	for _, v := range outputVals {
		output = v
		break
	}
	outputWR, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("Trying to create file, got : %w", err)
	}
	defer outputWR.Close()

	D.cryptData.in = inputRD
	D.cryptData.out = outputWR
	err = D.cryptData.Decrypt()
	return err 
}

func NewCryptData() cryptData {
	c := cryptData{
		h: header.GetDefaultHeader(),
		cr: cryptochunk.CryptChunk{},
		in: nil, 
		out: nil,
	}
	return c
} 

type cryptData struct {
	h header.FileHeader
	cr cryptochunk.CryptChunk
	salt []byte
	in, out *os.File
}

func (c cryptData) Encrypt() error {
	var headerBuf [128]byte 
	c.h.Encode(&headerBuf)
	headerBytesWriten, err := c.out.Write(headerBuf[:])
	if err != nil {
		return fmt.Errorf("Trying to write header buffer to file, got: %w", err)
	}
	if headerBytesWriten != len(headerBuf) {
		return fmt.Errorf("Number of bytes writen differs from the amount of bytes in headerBuf(128)")
	}
	saltBytesWriten, err := c.out.Write(c.salt)
	if err != nil {
		return fmt.Errorf("Trying to write salt buffer to file, got: %w", err)
	}
	if saltBytesWriten != len(c.salt) {
		return fmt.Errorf("Number of bytes writen: %d differs from the amount of bytes in c.salt: %d", saltBytesWriten, len(c.salt))
	}
	nonceBytesWriten, err := c.out.Write(c.cr.NonceSource)
	if err != nil {
		return fmt.Errorf("Trying to write nonce source buffer to file, got: %w", err)
	}
	if nonceBytesWriten != len(c.cr.NonceSource) {
		return fmt.Errorf("Number of bytes writen: %d differs from the amount of bytes in c.cr.NonceSource: %d", nonceBytesWriten, len(c.cr.NonceSource))
	}

	// cryptBuf and plainBuf are just cr.Out and cr.In
	// TODO:
	// their making should be done in handler, not here
	var chunksAmount uint16
	chunksAmount = uint16(0)
	var lastChunkSize uint16
	var readIntoPlain int
	var writeToOut int

	for {
		readIntoPlain, err = io.ReadFull(c.in, c.cr.In)
		if err == io.ErrUnexpectedEOF {
			break
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("Trying to read bytes from file into buffer, got: %w", err)
		}
		if readIntoPlain <= 0 {
			return fmt.Errorf("Have read invalid number of bytes: %d", readIntoPlain)
		} 
		chunksAmount++
		c.cr.ChunkPosition = chunksAmount 
		err = c.cr.Encrypt()
		if err != nil {
			return fmt.Errorf("Encrypting, got: %w", err)
		}
		writeToOut, err = c.out.Write(c.cr.Out)
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(c.cr.Out) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	if readIntoPlain < 0 {
		return fmt.Errorf("Invalid number of bytes read from file: negative: %d", readIntoPlain)
	}
	lastChunkSize = 0
	if readIntoPlain > 0 {
		lastChunkSize = uint16(readIntoPlain) + c.h.Overhead 
		c.cr.ChunkPosition = chunksAmount + 1
		err = c.cr.Encrypt()
		if err != nil {
			return fmt.Errorf("Encrypting, got: %w", err)
		}
		writeToOut, err = c.out.Write(c.cr.Out)
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(c.cr.Out) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	offset, err := c.out.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("Seeking for the start of the file to rewrite the header, got: %w", err)
	}
	if offset != 0 {
		return fmt.Errorf("Expected offset to be zero, but got: %d", offset)
	}
	c.h.ChunksAmount = chunksAmount
	c.h.LastChunkSize = lastChunkSize
	c.h.IsValid = true
	c.h.Encode(&headerBuf)
	headerBytesWriten, err = c.out.Write(headerBuf[:])
	if err != nil {
		return fmt.Errorf("Trying to write header buffer to file, got: %w", err)
	}
	if headerBytesWriten != len(headerBuf) {
		return fmt.Errorf("Number of bytes writen differs from the amount of bytes in headerBuf(128)")
	}
	return nil
}

func (c cryptData) Decrypt() error {
	var headerBuf [128]byte 
	readIntoHeaderBuf, err := c.in.Read(headerBuf[:])
	if err != nil {
		return fmt.Errorf("Reading header from file to buffer, got: %w", err)
	}
	if readIntoHeaderBuf != len(headerBuf) {
		return fmt.Errorf("Read wrong number of bytes. Must have been read %d bytes, but actualy read %d .", len(headerBuf), readIntoHeaderBuf)
	}
	c.h.Decode(&headerBuf)
	saltBuff := make([]byte, int(c.h.ArgonParams.SaltLength)) 
	readIntoSaltBuff, err := c.in.Read(saltBuff)
	if err != nil {
		return fmt.Errorf("Reading salt from file to buffer, got: %w", err)
	}
	if readIntoSaltBuff != int(c.h.ArgonParams.SaltLength) {
		return fmt.Errorf("Read wrong number of bytes. Must have been read %d bytes, but actualy read %d .", c.h.ArgonParams.SaltLength, readIntoSaltBuff)
	}

	argonParams := argon2id.Params{
		Header: c.h.ArgonParams,
		Salt: saltBuff,
	}
	key, err  := GetKey(argonParams)
	if err != nil {
		return fmt.Errorf("Geting key from user, got: %w", err)
	}

	nonceSource := make([]byte, c.h.NonceSourceLen)
	readIntoNonceSourceBuff, err := c.in.Read(nonceSource)
	if err != nil {
		return fmt.Errorf("Reading nonce source from file to buffer, got: %w", err)
	}
	if readIntoNonceSourceBuff != int(c.h.NonceSourceLen) {
		return fmt.Errorf("Read wrong number of bytes. Must have been read %d bytes, but actualy read %d .", c.h.NonceSourceLen, readIntoNonceSourceBuff)
	}
	crypter := aes256gcm.GetAES256GCM()
	c.cr.NonceSource = nonceSource

	overhead, err := crypter.GetOverhead(key)
	if err != nil {
		return fmt.Errorf("Getting overhead, got: %w", err)
	}
	plainDataChunkSize := c.h.ChunkSize - overhead 
	plainBuf := make([]byte, plainDataChunkSize)

	// Its a little bit strange that i redefine c here, maybe redesign
	c = cryptData{
		h: c.h,
		cr: cryptochunk.CryptChunk{
			In: make([]byte, c.h.ChunkSize),
			Out: plainBuf,
			Key: key,
			NonceSource: nonceSource,
			ChunkPosition: 0,
			Crypter: crypter,
		},
		salt: saltBuff,
		in: c.in,
		out: c.out,
	}

//	// What about comparison with c.h.NonceSourceLen ?
//	if readNonceSource != len(c.cr.NonceSource) {
//		return fmt.Errorf("Number of nonce source bytes read from file: %d differ from length of nonce source buffer: %d", readNonceSource, len(c.cr.NonceSource))
//	}
	var readIntoCrypt int
	var readIntoPlain int
	var writeToOut int
	var chunksPos int
	chunksAmount := int(c.h.ChunksAmount)
	for chunksPos=1;chunksPos<=chunksAmount;chunksPos++ {
		readIntoCrypt, err = c.in.Read(c.cr.In)
		// TODO: maybe remove ?
		if err == io.EOF && readIntoPlain == 0 {

		}
		if err != nil {
			return fmt.Errorf("Trying to read bytes from file into buffer, got: %w", err)
		}
		if readIntoCrypt <= 0 {
			return fmt.Errorf("Have read invalid number of bytes")
		} 

		c.cr.ChunkPosition = uint16(chunksPos)
		err = c.cr.Decrypt()
		if err != nil {
			return fmt.Errorf("Decrypting, got: %w", err)
		}
		writeToOut, err = c.out.Write(c.cr.Out)
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(c.cr.Out) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	if c.h.LastChunkSize != 0 {
		readIntoCrypt, err = c.in.Read(c.cr.In)
		if err != nil && err != io.EOF {
			return fmt.Errorf("Trying to read bytes from file into buffer, got: %w", err)
		}
		if readIntoCrypt <= 0 {
			return fmt.Errorf("Have read invalid number of bytes")
		} 
		c.cr.ChunkPosition = c.cr.ChunkPosition + 1
		err = c.cr.Decrypt()
		if err != nil {
			return fmt.Errorf("Decrypting, got: %w", err)
		}
		realData := (c.h.LastChunkSize - c.h.Overhead)
		writeToOut, err = c.out.Write(c.cr.Out[:realData])
		if err != nil {
			return fmt.Errorf("Writing to output file, got: %w", err)
		}
		if writeToOut != len(c.cr.Out[:realData]) {
			return fmt.Errorf("Writing wrong number of bytes to output file. Should be equal to size of output buffer, but differs.")
		}
	}
	return nil
}

func GetKey(P argon2id.Params) ([]byte, error) {
	fmt.Println("Provide password: ")
	s, err := term.ReadPassword(1)
	if err != nil {
		return nil, err
	}
	userKey := []byte(s)
	key, err := P.Hash(userKey)
	if err != nil {
		return nil, fmt.Errorf("Hashing, got: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("Invalid key length: %d", len(key))
	}
	return key, nil
}
