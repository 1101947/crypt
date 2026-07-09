package format

func encryptAes(in, out, key, nonce []byte) {
	err := aes256gcm.EncryptPtr(key, nonce, in, out)

}

func decrypt(in, out []byte) {
	nonce := GenerateNonce(x, nonceSource)
	err := aes256gcm.DecryptPtr(key, nonce, cipherData, plainData)
	if err != nil {
		return fmt.Errorf("Decrypting with aes256gcm, got: %w", err)
	}

}

func encryptStreamAes(){}
func decryptStreamAes(){}

func encryptStreamPoly(){}
func decryptStreamPoly(){}
