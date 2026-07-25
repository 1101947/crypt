package cli 

import (
	"fmt"
	"strings"

	"github.com/1101947/cliargumentrouter/cmdrouter"
	"github.com/1101947/cliargumentrouter/cmd"
)



// PROTOTYPES:
// GetHelpMsg() - define on Routers, handler, flags
//type Router struct {
//	handlers map[string]cmdrouter.Handler
//	helpMsg string 
//}

type Router map[string]cmdrouter.Handler

func NewRouter() Router {
	return Router{}
}

func (R Router) Handle(path []string, h cmdrouter.Handler) error {
	p := strings.Join(path, " ")
	if _, ok := R[p]; ok {
		return fmt.Errorf("Key is already exists.")
	}
	R[p] = h 
	return nil
}

func (R Router) HandleFunc(path []string, fn cmdrouter.ProcesserFunc) error {
	p := strings.Join(path, " ")
	if _, ok := R[p]; ok {
		return fmt.Errorf("Key is already exists.")
	}
	R[p] = fn 
	return nil
}


func (R Router) Process(posargs []string) (cmd.Cmd, error) {
	if len(posargs) == 0 {
		hlpMsg := GetHelpMsg()
		// TODO: should i return error here ? Invalid cliargs string should be considered error.
		// HERE
		return hlpMsg, nil 
	}
	h, foundOn, err := R.findHandler(posargs)
	if err != nil {
		return nil, err
	}
	posargs = posargs[foundOn:]
	cmnd, err := h.Process(posargs)
	if err != nil {
		return nil, err
	}
	return cmnd, nil
}

func (R Router) findHandler(posargs []string) (cmdrouter.Handler, int, error) {
	for  i:=len(posargs);i>0;i-- {
		p := strings.Join(posargs[:i], " ")
		h, ok := R[p]
		if ok {
			return h, i, nil
		}
	}
	return nil, 0, fmt.Errorf("Handler for command \"%v\"  not found\n %s", posargs, GetHelpMsg())
}

func NewVersionHandler(version string) versionHandler {
	return versionHandler(version)
}

type versionHandler string

func (v versionHandler) Exec() error {
	_, err := fmt.Println(string(v))
	return err 
}

func (v versionHandler) Process(posargs []string) (cmd.Cmd, error) {
	return v, nil
}

//func VersionCMD(posargs []string) error {
//	fmt.Println(linkvars.Version)
//	return nil
//}


func GetHelpMsg() helpMsg {
	// TODO: change this help message to something usefull.
	helpMsg := helpMsg("UNDER CONSTRUCTION. This help message needs changing.")
	return helpMsg 
}

type helpMsg string
func (h helpMsg) Exec() error {
	_, err := fmt.Println(h)
	return err
}


func HelpCMD(posargs []string) (cmd.Cmd, error) {
	helpMsg := GetHelpMsg()
	return helpMsg, nil
}
