package cli

import (
	"os"
	"fmt"
	"math"
	"strconv"
	"crypt/header"
	"crypt/cryptafile"
	"github.com/1101947/cliargumentrouter/flag"

)


type CryptHandler struct {
	cryptData cryptafile.CryptData
	interactive string
}

type EncryptHandler struct {
	Crypt CryptHandler 
}

func NewEncryptHandler() EncryptHandler {
	return EncryptHandler{
		Crypt: CryptHandler{
			cryptData: cryptafile.NewCryptData(),
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
			cryptData: cryptafile.NewCryptData(),
			interactive: "false",
		},
	}
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

	C.cryptData.In = inputRD
	C.cryptData.Out = outputWR
	return nil
}

func (E EncryptHandler) Process(posargs []string) error {
	E.Crypt.Process(posargs)
	defer E.Crypt.cryptData.In.Close()
	defer E.Crypt.cryptData.Out.Close()

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
		E.Crypt.cryptData.H.EncryptionFunction = cryptoFunc
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
		E.Crypt.cryptData.H.ChunkSize = uint16(chunkSize64)
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
		E.Crypt.cryptData.H.ArgonParams.Iterations= uint32(argonIteration64)
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
		E.Crypt.cryptData.H.ArgonParams.Memory = uint32(argonMemory64)
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
		E.Crypt.cryptData.H.ArgonParams.SaltLength= uint16(argonSaltLength64)
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
		E.Crypt.cryptData.H.ArgonParams.Parallelism = uint8(argonParallelism64)
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
	defer D.Crypt.cryptData.In.Close()
	defer D.Crypt.cryptData.Out.Close()

	// TODO: maybe put flags inside EncryptionHandler ?
	err = D.Crypt.cryptData.Decrypt()
	return err 
}

