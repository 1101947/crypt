package kdf

import ()

type ptrKdfArgs interface {
	newKdf (Kdf, error)
}

func (p argon2id.PtrParams) newKdf() (Kdf, error) {
}

func getKdfArgsFromCLI() {
}
