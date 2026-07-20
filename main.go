package main 

import (
	"log"
	"os"
	"crypt/cli"
)

func main() {
	router := cli.NewRouter()
	err := router.HandleFunc([]string{"version"}, cli.VersionCMD)
	if err != nil {
		log.Fatal(err)
	}
	err = router.HandleFunc([]string{"help"}, cli.HelpCMD)
	if err != nil {
		log.Fatal(err)
	}
	encryptHandler := cli.NewEncryptHandler()
	err = router.Handle([]string{"encrypt"}, encryptHandler)
	if err != nil {
		log.Fatal(err)
	}
	decryptHandler := cli.NewDecryptHandler()
	err = router.Handle([]string{"decrypt"}, decryptHandler)
	if err != nil {
		log.Fatal(err)
	}
	args := []string{}
	if isBuilt == "true" {
		if len(args) == 1 {
			args = []string{}
		} else {
			args = os.Args[1:]
		}
	} else {
		args = os.Args[2:]
	}
	err = router.Process(args)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	os.Exit(0)
}
