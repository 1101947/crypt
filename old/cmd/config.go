package cmd

import (
	"os"
	"io"
	"encoding/json"
	"path/filepath"
)

type path string

func (oldPath path) Update(newPath path) path {
	// TODO
	return newPath
}

type Path string

func (p path) String() string {
	return string(p)
}

func (P Path) Validate() (path, error) {
	// TODO
	return path(string(P)), nil
}

func (p path) Publish() Path {
	// TODO
	return Path(string(p))
}

type params bool

func (p params) IsEmpty() bool {
	// TODO
	return true
}

func (oldParams params) Update(newParams params) params {
	// TODO
	if !newParams.IsEmpty() {
		return newParams
	}
	return oldParams
}

type Params bool 

func (P Params) Validate() (params, error) {
	// TODO
	return params(bool(P)), nil
}

func (p params) Publish() Params {
	// TODO
	return Params(bool(p))
}

type action string

func (a action) IsEmpty() bool {
	// TODO
	return true
}

func (oldAction action)Update(newAction action) action {
	// TODO
	if !newAction.IsEmpty() {
		return newAction 
	}
	return oldAction
}



type Action string

func (A Action) Validate() (action, error) {
	// TODO
	return action(string(A)), nil
}

func (a action) Publish() Action {
	// TODO
	return Action(string(a))
}

type data []byte

func (d data) IsEmpty() bool {
	// TODO
	return true
}

func (oldData data) Update(newData data) data {
	// TODO
	if !newData.IsEmpty() {
		return newData
	}
	return oldData
}

type Data []byte

func (D Data) Validate() (data, error) {
	// TODO
	return data([]byte(D)), nil
}

func (d data) Publish() Data {
	// TODO
	return Data([]byte(d))
}

type config struct {
	params 
	action
	data 
	next path
}

func neWconfig() config {
	// TODO
	return config{}
}

func (cfg config) nextToParse() path {
	return cfg.next
}

func (cfg config) Update(newCfg config) config {
	cfg.params = (cfg.params).Update(newCfg.params)
	cfg.action = (cfg.action).Update(newCfg.action)
	cfg.data = (cfg.data).Update(newCfg.data)
	cfg.next = (cfg.next).Update(newCfg.next)
	return cfg
}

type Config struct {
	Params `json:"params"`
	Action `json:"action"`
	Data `json:"data"` 
	Next Path `json:"file to chainload"`
}

func NewConfig() Config {
	// TODO
	return Config{}
}

func (cfg Config) Validate() (config, error) {
	valid := config{}
	vParams, err := (cfg.Params).Validate()
	if err != nil {
		return valid, err 
	}
	vAction, err := (cfg.Action).Validate()
	if err != nil {
		return valid, err 
	}
	vData, err := (cfg.Data).Validate()
	if err != nil {
		return valid, err 
	}
	vNext, err := (cfg.Next).Validate()
	if err != nil {
		return valid, err 
	}
	valid = config{
		params: vParams,
		action: vAction,
		data: vData,
		next: vNext,
	}
	return valid, nil
}

func (cfg config) Publish() Config {
	pParams := (cfg.params).Publish()
	pAction := (cfg.action).Publish()
	pData := (cfg.data).Publish()
	pNext := (cfg.next).Publish()
	published := Config{
		Params: pParams,
		Action: pAction,
		Data: pData,
		Next: pNext,
	}
	return published
}

//type configFiles struct {
//	path string
//}
//
//func parseConfig(jsonPointer any, ) {
//}
//
//
//func getFilesToCompile(f path) (path, error) {
//	files := []path{}
//	subfiles := f.String())[:5] + ".d"
//	info, err := os.Stat(subfiles)
//	if !info.IsDir() {
//		return files, fmt.Errorf("File at path: %s  is not a directory")
//	}
//	if os.IsNotExist(err) {
//		return files, nil 
//	}
//	entries, err := os.ReadDir(subfiles)
//	if err != nil {
//		return files, err
//	}
//	for _, entry := range(entries) {
//		if isValidConfigFile() {
//			file := filepath.Join(f.String(), entry.Name)
//			toAppend, err := path(file)
//			if err != nil {
//				return files, err
//			}
//			files = append(files, toAppend)
//		}
//	}
//	return files, nil 
//}
//
//func compile(f filepath) {
//	filesToCompile, err := getFilesToCompile(f)
//	if err != nil {
//		return err 
//	}
//	cfg, err := compile(f, filepath(subfiles))
//}
//
func getConfigFile() (path, error) {
	// TODO
	tODOdir, err := filepath.Abs("./tmp/crypt.json")
	file := path(tODOdir)
	if err != nil {
		return file, err
	}
	return file, nil 
}

func getConfigFiles() ([]path, error) {
	// TODO
	files := []path{}
	mainConfigFile, err := getConfigFile()
	if err != nil {
		return files, err
	}
	files = append(files, mainConfigFile)
	return files, nil 
}

func parseFile(file path, pointer any) error {
	data, err := os.ReadFile(file.String())
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, pointer)
	if err != nil {
		return err
	}
	return nil 
}

func parseStdin(pointer any) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, pointer)
	if err != nil {
		return err
	}
	return nil 
}

func parseCli(pointer any) error {
	data := []byte(os.Args[1])
	err := json.Unmarshal(data, pointer)
	if err != nil {
		return err
	}
	return nil 
}

func parseConfigFile(file path) (config, error) {
	cfg := Config{}
	err := parseFile(file, &cfg)
	if err != nil {
		return neWconfig(), err
	}
	validatedCfg, err := cfg.Validate()
	if err != nil {
		return validatedCfg, err
	}
	next := validatedCfg.nextToParse()
	nCfg, err := parseConfigFile(next)
	if err != nil {
		return validatedCfg, err
	}
	validatedCfg = validatedCfg.Update(nCfg)
	if err != nil {
		return validatedCfg, err
	}
	return validatedCfg, nil
}

func parseConfig() (config, error) {
	cfg := neWconfig()
	files, err := getConfigFiles() 
	if err != nil {
		return cfg, err
	}
	for _, file := range(files) {
		nCfg, err := parseConfigFile(file)
		if err != nil {
			return cfg, err
		}
		cfg = cfg.Update(nCfg)
		if err != nil {
			return cfg, err
		}
	}
	stdinCfg := NewConfig()
	err = parseStdin(&stdinCfg)
	if err != nil {
		return cfg, err
	}
	validStdinCfg, err := stdinCfg.Validate()
	if err != nil {
		return cfg, err
	}
	cfg = cfg.Update(validStdinCfg)
	if err != nil {
		return cfg, err
	}
	cliCfg := NewConfig()
	err = parseCli(&cliCfg)
	if err != nil {
		return cfg, err
	}
	validCliCfg, err := cliCfg.Validate()
	if err != nil {
		return cfg, err
	}
	cfg = cfg.Update(validCliCfg)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

// config:
// - parameters
// - action
// - data
