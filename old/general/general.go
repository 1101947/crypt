package general

import (
	"math"
	"fmt"
)

func UintToUint32(u uint) (uint32, error) {
	if u > math.MaxUint32 {
		return 0, fmt.Errorf("uint size is bigger than maximum uint32 size")
	}
	return uint32(u), nil
}

func UintToUint8(u uint) (uint8, error) {
	if u > math.MaxUint8 {
		return 0, fmt.Errorf("uint size is bigger than maximum uint8 size")
	}
	return uint8(u), nil
}
