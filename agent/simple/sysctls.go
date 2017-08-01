package main

import (
	"io/ioutil"

	log "github.com/romana/rlog"
)

func ProvisionSysctls() error {

	for i, path := range kernelDefaults {
		if err := ioutil.WriteFile(path, []byte("1"), 0644); err != nil {
			log.Errorf("Error changing kernel parameter(%s): %s", path, err)
			return err
		}
		log.Debugf("%d: Succesfully enabled kernel parameter: %s", i, path)
	}

	log.Info("Successfully enabled kernel parameters for romana.")
	return nil
}
