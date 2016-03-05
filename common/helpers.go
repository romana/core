// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package common

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"os"
	"bufio"
)

// toBool is a convenience function that's like ParseBool
// but allows also "on"/"off" values.
func ToBool(val string) (bool, error) {
	s := strings.ToLower(val)
	switch s {
	case "yes":
		return true, nil
	case "on":
		return true, nil
	case "y":
		return true, nil
	case "true":
		return true, nil
	case "t":
		return true, nil
	case "1":
		return true, nil
	case "enabled":
		return true, nil
	case "no":
		return false, nil
	case "off":
		return false, nil
	case "n":
		return false, nil
	case "false":
		return false, nil
	case "f":
		return false, nil
	case "0":
		return false, nil
	case "disabled":
		return false, nil
	}
	return false, errors.New(fmt.Sprintf("Cannot convert %s to boolean", val))
}

func PressEnterToContinue() {
	fmt.Println("Press ENTER to continue")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
}

// MockPortsInConfig will take the config file specified
// and replace the ports with 0 to use arbitrary ports
// and write it out to /tmp/romana.yaml
func MockPortsInConfig(fname string) error {
	config, err := ReadConfig(fname)
	if err != nil {
		return err
	}
	services := []string{"root", "topology", "ipam", "agent", "tenant"}
	for i := range services {
		svc := services[i]
		config.Services[svc].Common.Api.Port = 0
		log.Printf("Set port for %s: %d\n", svc, config.Services[svc].Common.Api.Port)
	}

	return WriteConfig(config, "/tmp/romana.yaml")
}
