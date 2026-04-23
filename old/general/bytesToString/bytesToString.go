package bytesToString 

import (
	"fmt"
	"encoding/base64"
)

type BytesAs string

const (
	GoFormat BytesAs = "go format"
	Base64 BytesAs = "base64"
)

func BytesToString(bytes []byte, as BytesAs) (string, error) {
	if as == GoFormat {
		return fmt.Sprintf("%v", bytes), nil
	} else if as == Base64 {
		return base64.RawStdEncoding.EncodeToString(bytes), nil
	} else {
		return "", fmt.Errorf("Invalid bytes representation format")
	}
}
