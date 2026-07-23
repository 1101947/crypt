package cryptafile

import (
	"testing"
	"os"
	"fmt"
	"math/rand"
)

func getFilePath(s string) string {
	var projectName string = "crypt"
	var sep string = "/"
	pwd = strings.Split(os.Getwd(), "/")
	filepath := ".test__" + s
	for i:=len(pwd);i>=0;i-- {
		if pwd[i] == projectName {
			filepath = strings.Join(pwd[:i], sep) + filepath
			break
		}
	}
	return filepath
}

func createTestFileToEncrypt(buffSize, iterations int) (*os.File, error) {
	filepath := getFilePath("orig")
	fl, err := os.Create(filepath)
	if err != nil {
		return fl, fmt.Errorf("Creating file, got: %w", err)
	}
	randomBuff := make([]byte, buffSize)
	for i:=0;i<=iterations;i++ {
		n, err := rand.Read(randomBuff)
		if err != nil {
			return fl, fmt.Errorf("Reading random bytes into buffer, got %w", err)
		}
		if n != len(randomBuff) {
			return fl, fmt.Errorf("Wrote invalid number of random bytes: %d, should have been writen: %d", n, len(randomBuff))
		}
		fl.Write(randomBuff)
	} 
	return fl, nil
}

func compareFiles(size, amount int, orig, decr *os.File) bool {
	origBuff := make([]byte, size)
	decrBuff := make([]byte, size)
	origSha := sha256.New()
	decrSha := sha256.New()
	var origSum []byte
	var decrSum []byte
	for i:=0;i<=amount;i++ {
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
		if origSum != decrSum {
			return false, nil
		}
	}
	return true, nil

}

func TestNormalCrypt(t *testing.T) {
	fl, err := createTestFileToEncrypt(1024, 4)
	if err != nil {
		fl.Close()
		t.Errorf(err)
	}
	defer fl.Close()
	err = c.Encrypt()
	if err != nil {
		t.Errorf(err)
	}
	err = c.Decrypt()
	if err != nil {
		t.Errorf(err)
	}
	encFl, err := os.Create(getFileName("enc"))
	if err != nil {
		encFl.Close()
		t.Errorf(err)
	}


}
