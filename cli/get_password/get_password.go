package get_password

import (
	"syscall"

	"golang.org/x/term"
)

func GetPassword() ([]byte, error) {
    password, err := term.ReadPassword(int(syscall.Stdin))
    if err != nil {
        return nil, err
    }
    return password, nil
}
