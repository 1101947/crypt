package json

import (
	"fmt"
	"strings"
	"encoding/hex"

)

// element
//	whitespace
//	value
//		object
//		array
//		string
//		number
//		true
//		false
//		null

// state:
//	parsing Object
//		parsing string
//		parsing value
//	parsing array:
//		encounter [
//			if ] return 
//			if 
//

// state:
//	{ -> parsing Object
//		" -> parsing string -> "
//		" -> after key -> :
//		after value
//		parsing Pair
//			parsing Value
//	parsing Array
//		parsing Value
//	parsing Value
//		parsing String
//		parsing Number
//		parsing Bool or null
//		parsing Array
//		parsing Object
//
//	parse(str string) (json, string, error)
//
// alphabet:
//	- "
//	- :
//	- ,
// 	- {
//	- }
//	- [ 
//	- ] 
//	- t
//	- f 
//	- n
//	- 0-9 

//	- other - abort


const (
	jsonValue state = state("json value")
	jsonObject state = state("json object")
)

func splitStringByJsonWp(s string, whiteSpaces []string) []string {
	splited := []string{s}
	for _, wp := range(whiteSpaces) {
		newSplited := []string{}
		for _, str := range(splited) {
			newSplited = append(newSplited, (strings.Split(str, wp))...)
		}
		splited = newSplited
	}
	return splited
}


type structuralChar string

func (char structuralChar) is(s string) {
	if string(char) == s {
		return true
	} 
	return false
}

const (
	beginArray structuralChar = structuralChar("[")
	beginObject structuralChar = structuralChar("{")
	endArray structuralChar = structuralChar("]")
	endObject structuralChar = structuralChar("}")
	nameSeparator  structuralChar = structuralChar(":")
	valueSeparator  structuralChar = structuralChar(",")
)

func isWhitespace(s string) bool {
	whitespaces := getWhitespaces()
	for _, wp := range(whitespaces) {
		if s == wp {
			return true
		}
	}
	return false
}


func Parse2(s string) (json, error) {
	j := json{}
	if beginArray.is(s[0]) {
		json, err := parseArray(s[0:])
		if err != nil {
			return j, err
		}
		return j, nil
	}
	if beginObject.is(s[0]) {
		json, err := parseObject(s[0:])
		if err != nil {
			return j, err
		}
		return j, nil
	}
	return j, fmt.Errorf("Not a json. No opening brakcet found.")
}

func parseValue(s string, k uint) (json, uint, error) {
	for k=k;k<len(s);k++ {
		char := string(s[k])
		if isWhitespace(char) {
			continue
		} else if char == "t" {
			val, k, err := parseTrue(s, k+1)
			if err != nil {
				return k, j, err 
			}
			return val, k, nil
		} else if char == "f" {
			val, k, err := parseFalse(s, k+1)
			if err != nil {
				return k, j, err 
			}
			return val, k, nil
		} else if char == "n" {
			val, k, err := parseFalse(s, k+1)
			if err != nil {
				return k, j, err 
			}
			return val, k, nil
		} else if char == "\"" {
			val, k, err := parseString(s, k+1)
			if err != nil {
				return k, j, err 
			}
			return val, k, nil
		} else if char == "[" {
			val, k, err := parseArray(s, k+1)
			if err != nil {
				return k, j, err 
			}
			return val, k, nil
		} else if char == "{" {
			val, k, err := parseObject(s, k+1)
			if err != nil {
				return k, j, err 
			}
			return val, k, nil
		} else {
			nums := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
			for _, num := range(nums) {
				if char == num {
					val, k, err := parseNumber(s, k)
					if err != nil {
						return k, j, err 
					}
					return val, k, nil
				}
			}
			return k, j, fmt.Errorf("invalid charecter in value: %s", char)
		}
	}
}

func parseArray(s string, k uint) (uint, json, error) {
	j := jsonArray{}
	for k=k;k<len(s);k++ {
		char := string(s[k])
		if isWhitespace(char) {
			continue
		} 
		if j.Len() == 0 {
			k, val, err := parseValue(s, k)
			if err != nil {
				return k, j, err
			}
			j.Append(val)
		} else {
			if char == "," {
				if j.Length() == 0 {
					return k, j, fmt.Errorf("Invalid syntax, comma in the begging of the array")
				}
				k, val, err := parseValue(s, k) 
				if err != nil {
					return k, j, err
				}
				j.Append(val)
			} else if endArray.is(char) {
				return k+1, j, nil
			} else {
				return k, j, fmt.Errof("Parser Error. Error in parser implementation!")
			}
		}
	return k, j, fmt.Errorf("No closing bracket found")
}

func parseObject(s string, k uint) (uint, jsonObject, error) {
	j := jsonObject{}
	for k=k;k<len(s);k++ {
		char := string(s[k])
		if isWhitespace(char) {
			continue
		}
		if j.Len() == 0 {
			if char != "\"" {
				return k, j, fmt.Errof("Error parsing object. Invalid char %s in the beggining of the array", char)

			}
			k, pair, err := parsePair(s, k)
			if err != nil {
				return k, j, err
			}
			j.Append(pair)
		} else {
			if char == "," {
				k, pair, err := parsePair(s, k)
				if err != nil {
					return k, j, err
				}
				j.Append(pair)
			} else if char == "}" {
				return k+1, j, nil
			} else {
				return k, j, fmt.Errof("Error parsing json Object. Error in parser implementation.")
			}
		}
	}
	return j, fmt.Errorf("No closing bracket found")
}

func parsePair(s string, k uint) {
	j:= pair{}
	for k:=k;k<len(s);k++ {
		char := string(s[k])
		if isWhitespace(char) {
			continue
		}
		if !j.haveKey() {
			if char != "\"" {
				return k, j, fmt.Errorf("Error parsing object's pair. Invalid key syntax. Was expecting \" , got : %s", char)
			}
			k, key, err := parseString(s, k)
			j.addKey(key)
		} else {
			if char == ":" {
				k, val, err := parseValue(s, k+1)
				if err != nil {
					return k, j, err
				}
				j.addVal(val)
				return k, j, nil
			} else {
				return k, j, fmt.Errof("Error parsing Object's pair. Was expecting : , got : %s", char)
			}
		}
	}
	return k, j, fmt.Errof("Error parsing object's pair. Seems like json string ended on pair")
}

func Parse(s string) (json, error) {
	j := json{}
	whiteSpaces, err := getWhitespaces()
	if err != nil {
		return j, err
	}
	splited := splitStringByJsonWp(s, whiteSpaces)
	for k, v := range(splited) {
		fmt.Println(k, v)
	}
	return j, nil
}




// Private

type jsonWhiteSpace string

func getWhitespaces() ([]string, error) {
	wPs := []string{}
	wPs = append(wPs, " ")
	horizontalTab, err := hex.DecodeString("09")
	if err != nil {
		return wPs, err
	}
	wPs = append(wPs, string(horizontalTab))
	newLine, err := hex.DecodeString("0A")
	if err != nil {
		return wPs, err
	}
	wPs = append(wPs, string(newLine))
	carriageReturn, err := hex.DecodeString("0D")
	if err != nil {
		return wPs, err
	}
	wPs = append(wPs, string(carriageReturn))
	return wPs, nil
}

type jsonValue interface {
	Validate() (JsonValue, error)
	String() string
}
type jsonObject []jsonPair

//func (j jsonObject) Validate() (JsonValue, error) {
//	// TODO
//	return JsonValue{}, fmt.Errorf("")
//}

type jsonPair struct {
	key string
	value jsonValue
}

type jsonArray []jsonValue 

type jsonNumber string 

type jsonString string

type jsonLiteralName string

const (
	falsE jsonLiteralName = jsonLiteralName("false")
	null  jsonLiteralName = jsonLiteralName("null")
	truE jsonLiteralName = jsonLiteralName("true")
)

type json struct {
	tokens []jsonValue
}

// Public


type orType interface {
	setVariant()
	getVariants()
	id()
}

type JsonValue interface {
	Encode() (jsonValue, error)
}

type JsonObject []JsonPair 

type JsonPair struct {
	Key string
	Value JsonValue
}


type JsonArray []JsonValue 

