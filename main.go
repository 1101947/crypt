package main 

import (
	
	"log"
	//"bufio"
	//"strings"
	"os"
	//"fmt"
)

var version string = "NOVERSION"
var isBuilt string = "false"

func main() {
	router := NewRouter()
	err := router.HandleFunc([]string{"version"}, VersionCMD)
	if err != nil {
		log.Fatal(err)
	}
	err = router.HandleFunc([]string{"help"}, HelpCMD)
	if err != nil {
		log.Fatal(err)
	}
	//encryptHandler := NewEncryptHandler()
	//err = router.Handle([]string{"encrypt"}, encryptHandler)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//decryptHandler := NewDecryptHandler()
	//err = router.Handle([]string{"decrypt"}, decryptHandler)
	//if err != nil {
	//	log.Fatal(err)
	//}
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
		log.Fatal("ERROR: ", err, "\n", GetHelpMsg())
	}
	os.Exit(0)
}
