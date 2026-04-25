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
	err = router.HandleFunc([]string{"encrypt"}, EncryptCMD)
	if err != nil {
		log.Fatal(err)
	}
	err = router.HandleFunc([]string{"decrypt"}, DecryptCMD)
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
		log.Fatal(err)
	}

//
//
//	fmt.Println("Encrypt: ")
//	fmt.Printf("Enter source path: ")
//	reader := bufio.NewReader(os.Stdin)
//	sp, _ := reader.ReadString('\n')
//	sp = strings.TrimSpace(sp)
//	fmt.Printf("Enter destination path: ")
//	dp, _ := reader.ReadString('\n')
//	dp = strings.TrimSpace(dp)
//	c := cryptData{
//		sourcePath: sp,
//		destPath: dp,
//		symmCryptFuncToUse: "aes256gcm", 
//		slen: 16, 
//		iter: 1, 
//		mem: 64*1024,
//		klen: 32, 
//		paral: 4, 
//	}
//	//err := c.Encrypt()
//	err := c.Decrypt()
//	if err != nil {
//		log.Fatal(err)
//	}
	os.Exit(0)
}
