package cmd

import ()

func Run() error {
	_, err := parseConfig()
	if err != nil {
		return err
	}
	//cfg.run()
	return nil
	

}
