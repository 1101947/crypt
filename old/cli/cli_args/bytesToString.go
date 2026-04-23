package cli_args

import ()

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
	}
	return "", fmt.Errorf("Invalid bytes representation format")
}
