// Copyright (c) 2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// The package advertises list of networks by rerendering bird
// config file and optionally sending SIGHUP to the bird.
package bird

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"text/template"

	router "github.com/romana/core/routepublisher/publisher"
	"golang.org/x/sys/unix"
)

// Default implementation of router.Interface that publishes routes via
// bird BGP daemon.
type BirdRoutePublisher struct {
	// Connect to BGP
	*sync.Mutex

	// Name of template used to generate
	// bird config file
	templateFileName string

	// Name of a bird config file to generate
	birdConfigName string

	// .NeighborIP can be used inside the template
	// optional
	NeighborIP string

	// .NeighborAS can be used inside the template
	// optional
	NeighborAS string

	// Name of a pid file to read current pid pid from
	// mutually exclusive with `processName`
	pidFile string

	// .LocalAS can be used inside the template
	// optional
	LocalAS string

	// Extra output
	Debug bool

	// .Args available inside the template as a map
	Args map[string]interface{}

	// .Networks can be used inside the template
	Networks []net.IPNet
}

func New(config router.Config) (router.Interface, error) {
	var ok bool
	publisher := &BirdRoutePublisher{Mutex: &sync.Mutex{}}
	if publisher.templateFileName, ok = config["templateFileName"]; !ok {
		return nil, fmt.Errorf("Missing field templateFileName")
	}
	if publisher.birdConfigName, ok = config["birdConfigName"]; !ok {
		return nil, fmt.Errorf("Missing field birdConfigName")
	}
	publisher.NeighborIP, _ = config["neighborIP"]
	publisher.NeighborAS, _ = config["neighborAS"]
	publisher.pidFile, _ = config["pidFile"]

	if publisher.LocalAS, ok = config["localAS"]; !ok {
		return nil, fmt.Errorf("Parameter missing `localAS`")
	}

	if debug, ok := config["debug"]; ok && debug != "false" {
		publisher.Debug = true
	}

	return publisher, nil
}

// Update implements router.Interface by rendering new config file
// for the bird.
func (q *BirdRoutePublisher) Update(networks []net.IPNet, args map[string]interface{}) error {
	q.Lock()
	defer q.Unlock()
	log.Printf("Starting bgp update at %s -> %s:%s with %d networks", q.LocalAS, q.NeighborIP, q.NeighborAS, len(networks))

	q.Args = args
	q.Networks = networks
	template, err := template.ParseFiles(q.templateFileName)
	if err != nil {
		return err
	}

	// open file
	file, err := os.OpenFile(q.birdConfigName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// execute into file
	err = template.Execute(file, q)
	if err != nil {
		return err
	}

	// process sighup
	if q.pidFile != "" {
		pid, err := q.pidFromFile()
		if err != nil {
			return fmt.Errorf("Failed to read pid file %s, err=(%s)", q.pidFile, err)
		}

		process, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("Failed to find process with pid %d, err=(%s)", pid, err)
		}

		err = process.Signal(unix.SIGHUP)
		if err != nil {
			return fmt.Errorf("Failed to send SIGHUP to %d, err=(%s)", pid, err)
		}
	}

	log.Printf("Finished bgp update")
	return nil
}

func (q *BirdRoutePublisher) pidFromFile() (int, error) {
	file, err := os.Open(q.pidFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return 0, err
	}

	dataClean := bytes.Trim(data, "\n")
	pid, err := strconv.Atoi(string(dataClean))
	if err != nil {
		return 0, err
	}

	return pid, nil
}
