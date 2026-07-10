package header

import (
	"testing"
)

func TestFileHeader(t *testing.T) {
	testHeader := GetDefaultHeader()
	var buff [128]byte
	testHeader.Encode(&buff)
	newTestHeader := FileHeader{}
	newTestHeader.Decode(&buff)
	cmpString := Compare(testHeader, newTestHeader)
	if cmpString != "" {
		t.Errorf("Expected headers to be equal , but they are not. : %s", cmpString)
	}
}
