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
	result := isEqual(testHeader, newTestHeader)
	if result != true {
		t.Errorf("Expected headers to be equal , but they are not.")
	}
}
