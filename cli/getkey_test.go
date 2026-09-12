package cli

import (
	"testing"
	
	"github.com/1101947/crypt/argon2id"
)

func TestF(t *testing.T) {
	ap := argon2id.Params{
		Header: argon2id.GetDefaultHeader(),
		Salt: []byte("0000000000000000"),
	}
	c := cliKeyGetter("")
	_, err := c.GetKey(ap)
	if err != nil {
		t.Errorf("ERROR: %v", err)
	}
}
