package main 

import (
	
	"log"
	//"bufio"
	//"strings"
	"os"
	//"fmt"
)

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
	err = router.Process(os.Args[2:])
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
