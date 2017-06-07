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
	"log"
	"strings"

	"github.com/romana/core/common"
	"github.com/romana/core/server"
	log "github.com/romana/rlog"
)

func main() {
	endpointsStr := flag.String("etcd-endpoints", "localhost:2379", "Comma-separated list of etcd endpoints.")
	host := flag.String("host", "localhost", "Host to listen on.")
	port := flag.Int("port", 9600, "Port to listen on.")
	prefix := flag.String("etcd-prefix", "/romana", "Prefix to use for etcd data.")
	flag.Parse()
	if endpointsStr == nil {
		log.Errorf("No etcd endpoints specified")
		return
	}
	endpoints := strings.Split(endpointsStr, ",")
	romanad := &server.Romanad{addr: fmt.Sprintf("%s:%d", *host, *port)}

	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	storeConfig := common.StoreConfig{Endpoints: endpoints,
		Prefix: prefix,
	}
	svcInfo, err := common.InitializeService(romanad, storeConfig)
	if err != nil {
		log.Error(err)
		return
	}
	if svcInfo != nil {
		for {
			msg := <-svcInfo.Channel
			log.Info(msg)
		}
	}
}
