package header

import (
	"fmt"
	"testing"
)

func TestFileHeader(t *testing.T) {
	testHeader := GetDefaultHeader()
	testHeader.Version = 1
	testHeader.NonceSourceLen = 2
	testHeader.ChunkSize = 3
	testHeader.ChunksAmount = 4
	testHeader.LastChunkSize = 5
	testHeader.Overhead = 6 


	var buff [128]byte
	testHeader.Encode(&buff)
	newTestHeader := FileHeader{}
	newTestHeader.Decode(&buff)
	cmpString := Compare(testHeader, newTestHeader)
	if cmpString != "" {
		fmt.Printf("%+v \n \n %+v \n", testHeader, newTestHeader)
		t.Errorf("Expected headers to be equal , but they are not. : %s", cmpString)

	}
}
