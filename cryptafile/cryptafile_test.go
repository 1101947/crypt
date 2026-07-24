package cryptafile

import (
	"testing"

	"os"
	"fmt"
	"strings"
	"crypto/rand"
	"crypto/sha256"

	"crypt/argon2id"
)

func getFilePath(s string) (string, error) {
	var projectName string = "crypt"
	var sep string = "/"
	pwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("Getting pwd, got: %w", err) 
	}
	sPwd := strings.Split(pwd, "/")
	filepath := "/.test__/" + ".test__" + s
	for i:=len(sPwd)-1;i>=0;i-- {
		if sPwd[i] == projectName {
			filepath = strings.Join(sPwd[:i+1], sep) + filepath
			break
		}
	}
	return filepath, nil
}

func createTestFileToEncrypt(buffSize, iterations int) (*os.File, error) {
	filepath, err := getFilePath("orig")
	if err != nil {
		return nil, fmt.Errorf("Getting filepath, got: %w", err)
	}
	fl, err := os.Create(filepath)
	if err != nil {
		return fl, fmt.Errorf("Creating file, got: %w", err)
	}
	randomBuff := make([]byte, buffSize)
	for i:=0;i<iterations;i++ {
		n, err := rand.Read(randomBuff)
		if err != nil {
			return fl, fmt.Errorf("Reading random bytes into buffer, got %w", err)
		}
		if n != len(randomBuff) {
			return fl, fmt.Errorf("Wrote invalid number of random bytes: %d, should have writen: %d", n, len(randomBuff))
		}
		fl.Write(randomBuff)
	} 
	fl.Seek(0, 0)
	return fl, nil
}

func compareFiles(size, amount int, orig, decr *os.File) (bool, error) {
	origBuff := make([]byte, size)
	decrBuff := make([]byte, size)
	origSha := sha256.New()
	decrSha := sha256.New()
	var origSum []byte
	var decrSum []byte
	for i:=0;i<amount;i++ {
		nR, err := orig.Read(origBuff)
		if err != nil {
			return false, fmt.Errorf("Reading bytes to buffer, got: %w", err)
		}
		if nR != len(origBuff) {
			return false, fmt.Errorf("Read invalid number of bytes: %d, should have read: %d", nR, len(origBuff))
		}
		nD, err := decr.Read(decrBuff)
		if err != nil {
			return false, fmt.Errorf("Reading bytes to buffer, got: %w", err)
		}
		if nD != len(decrBuff) {
			return false, fmt.Errorf("Read invalid number of bytes: %d, should have read: %d", nD, len(decrBuff))
		}
		origSha.Write(origBuff)
		decrSha.Write(decrBuff)
		origSum = origSha.Sum(nil)
		decrSum = origSha.Sum(nil)
		if string(origSum) != string(decrSum) {
			return false, nil
		}
	}
	return true, nil

}

func TestNormalCrypt(t *testing.T) {
	var size int = 1024
	var amount int = 4
	origFl, err := createTestFileToEncrypt(size, amount)
	defer origFl.Close()
	if err != nil {
		t.Fatal("ERROR: creating original file, got: ", err.Error())
	}
	encFlPath, err := getFilePath("enc")
	if err != nil {
		t.Fatal("ERROR: getting file path for encrypted file, got: ", err.Error())
	}
	encFl, err := os.Create(encFlPath)
	defer encFl.Close()
	if err != nil {
		t.Fatal("ERROR: creating encrypted file, got: ", err.Error())
	}
	cr := NewCryptData()
	//
	cr.Salt, err = argon2id.GetSalt(cr.H.ArgonParams.SaltLength) 
	if err != nil {
		t.Errorf("ERROR: getting salt, got: %s", err.Error())
	}
	//tk := tKeyGetter{}
	arg := argon2id.Params{
		Header: cr.H.ArgonParams,
		Salt: cr.Salt,
	}
	gtr, err := getKeyGetter(arg)
	if err != nil {
		t.Fatal("ERROR: getting key getter, got: ", err.Error())
	}
	cr.KeyGetter = gtr 

	cr.In = origFl
	cr.Out = encFl
	err = cr.Encrypt()
	if err != nil {
		t.Fatal("ERROR: Encrypting, got: ", err.Error())
	}
	decFlPath, err := getFilePath("dec")
	if err != nil {
		t.Fatal("ERROR: getting file path for the decrypted file, got: ", err.Error())
	}
	decFl, err := os.Create(decFlPath)
	defer decFl.Close()
	if err != nil {
		t.Fatal("ERROR: creatng decrypted file, got: ", err.Error())
	}

	cr = NewCryptData()

	encFl.Seek(0, 0)
	cr.In = encFl 
	cr.Out = decFl
	cr.KeyGetter = gtr 
	err = cr.Decrypt()
	if err != nil {
		t.Fatal("ERROR: decrypting, got: ", err.Error())
	}

	decFl.Seek(0, 0)
	origFl.Seek(0, 0)
	isEq, err := compareFiles(size, amount, origFl, decFl)
	if err != nil {
		t.Fatal("ERROR: comparing two files, got: ", err.Error())
	}
	if !isEq {
		t.Errorf("Decrypted file differs from orginal!")
	}
}

type tKeyGetter struct {
	b []byte
}

func (t tKeyGetter) GetKey(a argon2id.Params) ([]byte, error) {
	return t.b, nil
}

func getKeyGetter(a argon2id.Params) (tKeyGetter, error) {
	userKey := make([]byte, a.Header.KeyLength)
	i, err := rand.Read(userKey)
	if i != len(userKey) {
		return tKeyGetter{}, fmt.Errorf("Read invalid number of random bytes: %d , should have read: %d", i, len(userKey)) 
	}
	key, err := a.Hash(userKey)
	if err != nil {
		return tKeyGetter{}, fmt.Errorf("Hashing, got: %w", err)
	}
	if len(key) != 32 {
		return tKeyGetter{}, fmt.Errorf("Invalid key length: %d", len(key))
	}
	return tKeyGetter{ b: key, }, nil
}
