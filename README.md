# Crypt
is a simple encryption utility.

# Notice
Not production ready !

# Installation
## Downloading source code
``` sh
git clone https://github.com/1101947/crypt.git
```
## Building:
``` sh
go build -ldflags="-X 'main.IsBuilt=true' -X 'main.Version=v$(git show -s --format=%cd --date=iso-strict HEAD)__$(git rev-parse --short HEAD)'" -o crypt *.go
```
## System installation:
Simply put generated executable "crypt" in current directory in any PATH directory of your liking, for example:
``` sh
cp crypt ~/.local/bin/crypt
```

# Usage
To encrypt file, run:
``` sh
crypt encrypt --input="path-to-the-file-to-encrypt" --output="path-to-the-encrypted-file"
```
To decrypt file, run:
``` sh
crypt decrypt --input="path-to-the-encrypted-file" --output="path-to-the-decrypted-file"
```
# License
This project is licensed uder GPLv3, for more information see LICENSE.txt

# TODO:
- store hmac/aead in header to verify it(header) and optionaly allow user to use securely stored version to protect from replay attack(replace valid encrypted file with another version of valid encrypted file) 
- add size check(check for number of numbers that chunkPosition can hold, safe amount of data you can encrypt with different nonces and same key for aes256gcm and chacha20poly1305)
- add verification function/method for header and cryptData(crypt.go)
- add option to enable progress bar while en/decrypting
- add tests, try to decrypted tampered files, try to change header bytes and random bytes, see how decryption will go.
- add Verify for argon header. KeyLen must be 32 byte long for both aes256gcm and chacha20poly1305. Remove user flag for setting key length.


# Further text needs editing and not for reference.
# File format description
TODO:
Formats:
    Stream:
        Starts with the header, but without information about chunks amount and last chunk size.
        Then goes chunks , with first byte being a final/notfinal flag.
        When steam ends and amount of information is less then space in normal chunk two final chunks are send:
        Firs contains final bytes and zeros at the end and second length of the real information at the first one. Both the same length as normal chunks.
        //If final flag is set, chunk is considered to be one of finilizing series(there may be several, because size of the last one may be lesser then size of a normal chunk , but bigger than space left to encode it in last chunk(normal chunk size - length of the last one)
    Fixed header:
        Starts with the fixed header just like streamed one, but contains information about chunks amount and last chunk size.
    Dynamic header:
        Starts with the same header as streamed one , but chunks doesn't have a finality flag and also file has dynamic header at the end, which contains merkle tree and table/log

# 0: Fixed header only file 
{ Header: {
    Magic: [4]byte, // CRPT
    Version: int64, // timestamp
    Type: uint8, // 0 for fixed header only file, 1 for stream, 2 for dynamic header 
    IsValid: bool, // validity
    IsLittleEndian,
    EncryptionFunction [16]byte, // argon2id
    NonceSourceLen uint16,
    ChunksAmount uint16,
    LastChunkSize uint16,
    ArgonParams argon2id.Header,
    }, 
  Body: {
    chunks [][]byte
}}
# 1: Stream 
{ Header: {
    Magic: [4]byte, // CRPT
    Version: int64, // timestamp
    Type: uint8, // 0 for fixed header only file, 1 for stream, 2 for dynamic header 
    IsValid: bool, // validity
    IsLittleEndian,
    EncryptionFunction [16]byte, // argon2id
    NonceSourceLen uint16,
    ArgonParams argon2id.Header,
    }, 
  Body: {
     is_last encrypted
    [0       ------------------------------]
    [0       ------------------------------]
    ...
    [1       ---------------------------000]
             length of the last chunk data
    [1       14                            ] 

}}
# 1: Dynamic header at the end 
{ Header: {
    Magic: [4]byte, // CRPT
    Version: int64, // timestamp
    Type: uint8, // 0 for fixed header only file, 1 for stream, 2 for dynamic header 
    IsValid: bool, // validity
    IsLittleEndian,
    EncryptionFunction [16]byte, // argon2id
    NonceSourceLen uint16,
    ChunksAmount uint16,
    LastChunkSize uint16,
    ArgonParams argon2id.Header,
    }, 
  Body: {
     encrypted
    [------------------------------]
    [------------------------------]
    .
    [---------------------------000]
}
  Endtable: {
    Merkle tree
    Journal/table:
    offsets: [234, 32124, 325262, 32343, 2432] # block 1 is located at offset 234, block 2 at 32124 and so on
}
}


Funcs:
EncodeFileChunk
DecodeFileChunk
EncodeStreamChunk
DecodeSreamChunk
WriteHeader(Streamed, fixed(start)header, dynamic(end)header)

Fixed-header format:
    Encrypt():
        Parallel access input:
            Encrypt chunk by chunk
        Random access input:
            Calculate cryptChunk and dataChunk size.
            Parallel encryption
?TLV-chunked format
?escaped format:

Encrypt parallel/random access -> parallel 
Decrypt parallel access -> parallel/random 
## Consider:
- adding  Steam format for streaming - each chunk have length field.
// type Stream struct {}

Escaped - not sure if it has any usecase, maybe if human readability or hign noise level resistance needed.
// type Escaped struct {}

- adding authentication(AEAD/HMAC for header)

## File format description:
File format consists of Header, fixed size chunks and final chunk with variable(from 1 byte to size of fixed size chunk - 1 byte).
Header consists of fields:
1) Nonce source size - size of Nonce source array
2) Nonce source - a random array of bytes from which chunk nonce will be derived(chunk nonce = Nonce source XOR chunk position)
3) Encryption function - 


