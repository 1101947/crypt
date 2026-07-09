package format

type Crypt struct {
	In, Out, Key, NonceSource []byte
	// TODO: what is overflow ?
	ChunkPosition int64
}

func (C Crypt) encryptAes() {
	nonce := GenerateNonce12Bytes(C.ChunkPosition,C.NonceSource)
	err := aes256gcm.EncryptPtr(key, nonce, in, out)
	if err != nil {
		return fmt.Errorf("Encrypting data at pointer, got %w", err)
	}

}

func (C Crypt) decryptAes() {
	nonce := GenerateNonce12Bytes(C.ChunkPosition, C.NonceSource)
	err := aes256gcm.DecryptPtr(C.Key, nonce, C.CipherData, C.PlainData)
	if err != nil {
		return fmt.Errorf("Decrypting with aes256gcm, got: %w", err)
	}

}

// assumption : uint64 is 8bytes long
//              nonce and nonce source is 12bytes long
// TODO: make sure this works correctly
func GenerateNonce12Bytes(source []byte, chunkNumber int) []byte {
	buf = make([]byte, 8, 12)
	binary.LittleEndian.PutUint64(buf, chunkNumber)
	newnonce make([]byte, 12)
	for i:=0; i<12; i++ {
		newnonce[i] = buf[i] ^ source[i]
		
	}
	return newnonce

}

//func encryptStreamAes(){}
//func decryptStreamAes(){}
//
//func encryptStreamPoly(){}
//func decryptStreamPoly(){}
