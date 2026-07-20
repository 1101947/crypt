package main

import (
	"fmt"
	"strings"

	"github.com/1101947/cliargumentrouter/cmdrouter"
)

//type Router map[string]cmdrouter.Handler


// GetHelpMsg() - define on Routers, handler, flags
type Router struct {
	handlers map[string]cmdrouter.Handler
	helpMsg string 
}

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


func (R Router) Process(posargs []string) error {
	if len(posargs) == 0 {
		fmt.Println(GetHelpMsg())
		return nil
	}
	h, foundOn, err := R.findHandler(posargs)
	if err != nil {
		return err
	}
	posargs = posargs[foundOn:]
	err = h.Process(posargs)
	if err != nil {
		return err
	}
	return nil
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

func VersionCMD(posargs []string) error {
	fmt.Println(version)
	return nil
}

func GetHelpMsg() string {
	// TODO: change this help message to something usefull.
	helpMsg := "UNDER CONSTRUCTION. This help message needs changing."
	return helpMsg 
}

func HelpCMD(posargs []string) error {
	fmt.Println(GetHelpMsg())
	return nil
}
