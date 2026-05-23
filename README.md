# Crypt

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

## TODO:
- read and encrypt large streams of byte by chuncks, with io.Reader([]byte) instead of io.ReadAll([]byte)
- store hmac/aead in header to verify it and optionaly allow user to use securely stored version to protect from replay attack(replace valid encrypted file with another version of valid encrypted file) 

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
