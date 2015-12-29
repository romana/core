// Copyright (c) 2015 Pani Networks
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
	"log"
)

// MockPortsInConfig will take the config file specified
// and replace the ports with 0 to use arbitrary ports 
// and write it out to /tmp/romana.yaml
func MockPortsInConfig(fname string) error {
	config,err := ReadConfig(fname)
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
