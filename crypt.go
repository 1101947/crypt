package main
//
import (
	"io"
	"os"
	"fmt"
	"math"
	"strconv"
	"crypto/rand"
	"crypt/argon2id"
	"crypt/aes256gcm"
	"crypt/chacha20poly1305"
	"crypt/header"
	"crypt/cryptochunk"
	"golang.org/x/term"
	"github.com/1101947/cliargumentrouter/flag"
)

type CryptHandler struct {
	cryptData cryptData
	interactive string
}

type EncryptHandler struct {
	Crypt CryptHandler 
}

func NewEncryptHandler() EncryptHandler {
	return EncryptHandler{
		Crypt: CryptHandler{
			cryptData: NewCryptData(),
			interactive: "false",
		},
	}
}

type DecryptHandler struct {
	Crypt CryptHandler 
}

func NewDecryptHandler() DecryptHandler {
	return DecryptHandler{
		Crypt: CryptHandler{
			cryptData: NewCryptData(),
			interactive: "false",
		},
	}
}

func NewCryptData() cryptData {
	c := cryptData{
		h: header.GetDefaultHeader(),
		cr: cryptochunk.CryptChunk{},
		salt: nil,
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


func (C *CryptHandler) Process(posargs []string) error {
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

	C.cryptData.in = inputRD
	C.cryptData.out = outputWR
	return nil
}

func (E EncryptHandler) Process(posargs []string) error {
	E.Crypt.Process(posargs)
	defer E.Crypt.cryptData.in.Close()
	defer E.Crypt.cryptData.out.Close()

	flags := flag.DefaultFlags("--", "=", posargs)
	err := flags.Parse()
	if err != nil {
		return fmt.Errorf("Parsing cli arguments, got: %w", err)
	}
	kwargs, posargs := flags.Extract()

	// TODO: add flag for endianness
	cryptoFuncs, ok := kwargs["encryption-function"]
	if ok {
		if len(cryptoFuncs) != 1 {
			return fmt.Errorf("Only one encryption-function argument may be specified. You provided %d arguments.", len(cryptoFuncs))
		}
		var cryptoFuncStr string
		for _, v := range cryptoFuncs {
			cryptoFuncStr = v
			break
		}
		if (cryptoFuncStr != "aes256gcm") && (cryptoFuncStr != "chacha20poly1305") {
			return fmt.Errorf("Invalid encryption function specified: %s . Must be either aes256gcm or chacha20poly1305.", cryptoFuncStr)
		}
		var cryptoFunc [header.EncryptionFunctionNameSize]byte
		cryptoFuncBytesCopied := copy(cryptoFunc[:], cryptoFuncStr)
		if cryptoFuncBytesCopied != len(cryptoFuncStr) {
			return fmt.Errorf("Wrong number of bytes copied, while copying encryption fucntion name: %d . Should have been copied %d", cryptoFuncBytesCopied, header.EncryptionFunctionNameSize)
		}
		E.Crypt.cryptData.h.EncryptionFunction = cryptoFunc
	}
	chunkSizes, ok := kwargs["chunk-size"]
	if ok {
		if len(chunkSizes) != 1 {
			return fmt.Errorf("Only one chunk-size argument may be specified. You provided %d arguments.", len(chunkSizes))
		}
		var chunkSizeStr string
		for _, v := range chunkSizes {
			chunkSizeStr = v
			break
		}
		// TODO: add option to use big endian
		// TODO: maybe add check on whether system is 64 or 32 , and use 32 as third parameter if system is 32bit
		// It seems to me, that strconv.ParseUint just doesnt fail when value is too big, just silently trims it.
		chunkSize64, err := strconv.ParseUint(chunkSizeStr, 10, 64)
		if err != nil {
			return fmt.Errorf("Parsing chunk-size to uint64, got: %w", err)
		}
		if chunkSize64 > math.MaxUint16 {
			return fmt.Errorf("Your chunk-size value is too big: %d", chunkSize64)
		}
		E.Crypt.cryptData.h.ChunkSize = uint16(chunkSize64)
	}
	argonIterations, ok := kwargs["argon-iteration"]
	if ok {
		if len(argonIterations) != 1 {
			return fmt.Errorf("Only one argon-iteration argument may be specified. You provided %d arguments.", len(argonIterations))
		}
		var argonIteration string
		for _, v := range argonIterations {
			argonIteration = v
			break
		}
		argonIteration64, err := strconv.ParseUint(argonIteration, 10, 64)
		if err != nil {
			return fmt.Errorf("Parsing argon-iteration to uint64, got: %w", err)
		}
		if argonIteration64 > math.MaxUint32 {
			return fmt.Errorf("Your argon-iteration value is too big: %d . Maximum value is: %d", argonIteration64, math.MaxUint32)
		}
		E.Crypt.cryptData.h.ArgonParams.Iterations= uint32(argonIteration64)
	}
	argonMemories, ok := kwargs["argon-memory"]
	if ok {
		if len(argonMemories) != 1 {
			return fmt.Errorf("Only one argon-memory argument may be specified. You provided %d arguments.", len(argonMemories))
		}
		var argonMemoryStr string
		for _, v := range argonMemories {
			argonMemoryStr = v
			break
		}
		argonMemory64, err := strconv.ParseUint(argonMemoryStr, 10, 64)
		if err != nil {
			return fmt.Errorf("Parsing argon-memory to uint64, got: %w", err)
		}
		if argonMemory64 > math.MaxUint32 {
			return fmt.Errorf("Your argon-memory value is too big: %d . Maximum value is: %d", argonMemory64, math.MaxUint32)
		}
		E.Crypt.cryptData.h.ArgonParams.Memory = uint32(argonMemory64)
	}
	argonSaltLengths, ok := kwargs["argon-salt-length"]
	if ok {
		if len(argonSaltLengths) != 1 {
			return fmt.Errorf("Only one argon-salt-length argument may be specified. You provided %d arguments.", len(argonSaltLengths))
		}
		var argonSaltLengthStr string
		for _, v := range argonSaltLengths {
			argonSaltLengthStr = v
			break
		}
		argonSaltLength64, err := strconv.ParseUint(argonSaltLengthStr, 10, 64)
		if err != nil {
			return fmt.Errorf("Parsing argon-salt-length to uint64, got: %w", err)
		}
		if argonSaltLength64 > math.MaxUint16 {
			return fmt.Errorf("Your argon-salt-length value is too big: %d . Maximum value is: %d", argonSaltLength64, math.MaxUint16)
		}
		E.Crypt.cryptData.h.ArgonParams.SaltLength= uint16(argonSaltLength64)
	}
	argonParallelisms, ok := kwargs["argon-parallelism"]
	if ok {
		if len(argonParallelisms) != 1 {
			return fmt.Errorf("Only one argon-parallelism argument may be specified. You provided %d arguments.", len(argonParallelisms))
		}
		var argonParallelismStr string
		for _, v := range argonParallelisms {
			argonParallelismStr = v
			break
		}
		argonParallelism64, err := strconv.ParseUint(argonParallelismStr, 10, 64)
		if err != nil {
			return fmt.Errorf("Parsing argon-parallelism to uint64, got: %w", err)
		}
		if argonParallelism64 > math.MaxUint8 {
			return fmt.Errorf("Your argon-parallelism value is too big: %d . Maximum value is: %d", argonParallelism64, math.MaxUint8)
		}
		E.Crypt.cryptData.h.ArgonParams.Parallelism = uint8(argonParallelism64)
	}

	// TODO: maybe put flags inside EncryptionHandler ?
	err = E.Crypt.cryptData.Encrypt()
	return err 
}

func (D DecryptHandler) Process(posargs []string) error {
	err := D.Crypt.Process(posargs)
	if err != nil {
		return err
	}
	defer D.Crypt.cryptData.in.Close()
	defer D.Crypt.cryptData.out.Close()

	// TODO: maybe put flags inside EncryptionHandler ?
	err = D.Crypt.cryptData.Decrypt()
	return err 
}

func (c cryptData) Encrypt() error {
	//argonHeader := argon2id.GetDefaultHeader()
	argonHeader := c.h.ArgonParams
	salt, err := argon2id.GetSalt(argonHeader.SaltLength)
	if err != nil {
		return fmt.Errorf("Generating salt for argon2id function, got: %w", err)
	}
	argonParams := argon2id.Params{
		Header: argonHeader,
		Salt: salt,
	}
	key, err  := GetKey(argonParams)
	if err != nil {
		return fmt.Errorf("Geting key from user, got: %w", err)
	}
	// TODO: select crypter based on header.cryptofunc

	cryptoFuncName := string(c.h.EncryptionFunction[:])
	if cryptoFuncName[:9] == "aes256gcm" {
		c.cr.Crypter = aes256gcm.GetAES256GCM()
	} else if cryptoFuncName == "chacha20poly1305" {
		c.cr.Crypter = chacha20poly1305.GetChaCha20Poly1305()
	} else {
		return fmt.Errorf("Ivalid encryption function option in header: %s", cryptoFuncName)
	}

	overhead, err := c.cr.Crypter.GetOverhead(key)

	if err != nil {
		return fmt.Errorf("Getting overhead, got: %w", err)
	}
	c.h.Overhead = overhead 

	nonceSourceLen, err := c.cr.Crypter.GetNonceSize(key)
	if err != nil {
		return fmt.Errorf("Getting nonce source size, got: %w", err)
	}
	c.h.NonceSourceLen = nonceSourceLen
	nonceSource := make([]byte, nonceSourceLen)
	nonceSourceBytesRead, err := rand.Read(nonceSource)
	if err != nil {
		return fmt.Errorf("Reading random bytes into nonceSource buffer, got: %w", err)
	}
	if nonceSourceBytesRead != int(nonceSourceLen) {
		return fmt.Errorf("Reading random bytes into nonceSource buffer: number of bytes should be equal to nonceSourceLen: %d, but is: %d", nonceSourceLen, nonceSourceBytesRead)
	}
	plainDataChunkSize := c.h.ChunkSize - overhead 
	plainBuf := make([]byte, int(plainDataChunkSize))
	c = cryptData{
		h: c.h,
		cr: cryptochunk.CryptChunk{
			In: plainBuf,
			Out: make([]byte, c.h.ChunkSize),
			Key: key,
			NonceSource: nonceSource,
			ChunkPosition: 0,
			Crypter: c.cr.Crypter,
		},
		salt: salt,
		in: c.in,
		out: c.out,
	}

	var headerBuf [128]byte 
	c.h.Encode(&headerBuf)
	headerBytesWriten, err := (c.out).Write(headerBuf[:])
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
			return fmt.Errorf("Encrypting last chunk, got: %w", err)
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
	c.cr.NonceSource = nonceSource
	// HERE
	fmt.Printf("DEBUG: %d\n", c.h.NonceSourceLen)
	cryptoFuncName := string(c.h.EncryptionFunction[:])
	if cryptoFuncName[:9] == "aes256gcm" {
		c.cr.Crypter = aes256gcm.GetAES256GCM()
	} else if cryptoFuncName == "chacha20poly1305" {
		c.cr.Crypter = chacha20poly1305.GetChaCha20Poly1305()
	} else {
		return fmt.Errorf("Ivalid encryption function option in header: %s", cryptoFuncName)
	}

	overhead, err := c.cr.Crypter.GetOverhead(key)
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
			Crypter: c.cr.Crypter,
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
