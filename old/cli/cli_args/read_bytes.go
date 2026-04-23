package cli_args

import (
	"os"
)

func getBytes(shortFlag, longFlag string, defaultValue []byte) ([]byte, error) {
	args := os.Args
	valueToReturn := defaultValue
	strValue := ""
	counter := 0
	for _, arg := range args {
		if arg[:len(shortFLag)] == shortFlag {
			counter++
			strValue = arg[len(shortFlag)+1:]
		} else if arg[:len(longFlag)] == longFlag {
			counter++
			strValue = arg[len(longFLag)+1:]
		}
	}
	if counter == 0 {
		return defaultValue 
	} else if counter == 1 {
		_, err := fmt.Sscanf(strValue, "%v", &valueToReturn)
		if err != nil {
			valueToReturn, err = base64.RawStdEncoding.Stritc().DecodeString(strValue)
			if err != nil {
				return nil, err
			}
			return valueToReturn, nil
		}
		return valueToReturn, nil
	}
	return nil, fmt.Errorf("Found multiple getBytes flag")
}



