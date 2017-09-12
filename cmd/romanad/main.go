// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Command for running the IPAM service.
package main

import (
	"flag"
	"fmt"

	"io/ioutil"
	"os"
	"strings"

	"github.com/romana/core/common"
	"github.com/romana/core/common/client"
	"github.com/romana/core/server"
	log "github.com/romana/rlog"
)

func main() {
	endpointsStr := flag.String("etcd-endpoints", client.DefaultEtcdEndpoints, "Comma-separated list of etcd endpoints.")
	host := flag.String("host", "localhost", "Host to listen on.")
	port := flag.Int("port", 9600, "Port to listen on.")
	prefix := flag.String("etcd-prefix", client.DefaultEtcdPrefix, "Prefix to use for etcd data.")
	topologyFile := flag.String("initial-topology-file", "", "Initial topology")
	flag.Parse()
	if endpointsStr == nil {
		log.Errorf("No etcd endpoints specified")
		os.Exit(1)
	}
	endpoints := strings.Split(*endpointsStr, ",")
	romanad := &server.Romanad{Addr: fmt.Sprintf("%s:%d", *host, *port)}

	pr := *prefix
	if !strings.HasPrefix(pr, "/") {
		pr = "/" + pr
	}

	var topology string

	if *topologyFile != "" {
		topoBytes, err := ioutil.ReadFile(*topologyFile)
		if err != nil {
			log.Errorf("Cannot read initial-topology-file %s: %s", *topologyFile, err)
			os.Exit(2)
		}
		topology = string(topoBytes)
	}

	config := common.Config{EtcdEndpoints: endpoints,
		EtcdPrefix:      pr,
		InitialTopology: topology,
	}
	svcInfo, err := common.InitializeService(romanad, config)
	if err != nil {
		log.Error(err)
		os.Exit(3)
	}
	if svcInfo != nil {
		for {
			msg := <-svcInfo.Channel
			log.Info(msg)
		}
	}
}
