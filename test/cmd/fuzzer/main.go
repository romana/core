// Copyright (c) 2016-2017 Pani Networks
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

// Command for running the Kubernetes Listener.
package main

import (
	"flag"
	"fmt"
	"net"

	"os"
	"strings"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
	log "github.com/romana/rlog"
)

func main() {
	var err error
	endpointsStr := flag.String("etcd-endpoints", client.DefaultEtcdEndpoints, "Comma-separated list of etcd endpoints.")
	prefix := flag.String("etcd-prefix", client.DefaultEtcdPrefix, "Prefix to use for etcd data.")
	flag.Parse()
	if endpointsStr == nil {
		log.Errorf("No etcd endpoints specified")
		os.Exit(1)
	}
	endpoints := strings.Split(*endpointsStr, ",")

	pr := *prefix
	if !strings.HasPrefix(pr, "/") {
		pr = "/" + pr
	}
	config := common.Config{EtcdEndpoints: endpoints,
		EtcdPrefix: pr,
	}
	cl, err := client.NewClient(&config)
	if err != nil {
		panic(err)
	}
	tags := make(map[string]string)
	i := 0
	for {
		i++
		log.Infof("In fuzzer, with %d", i)
		ip := net.ParseIP(fmt.Sprintf("10.10.10.%d", i))
		tags[fmt.Sprintf("key%d", i)] = fmt.Sprintf("val%d", i)
		hostName := fmt.Sprintf("fuzzerhost%d", i)
		host := api.Host{IP: ip,
			Name: hostName,
			Tags: tags,
		}
		log.Infof("Adding host %s", hostName)
		err = cl.IPAM.AddHost(host)
		if err != nil {
			panic(err)
		}
		log.Infof("Added host OK")
		addr := fmt.Sprintf("addr%d", i)
		log.Infof("Trying to allocate IP for %s", addr)
		ip, err := cl.IPAM.AllocateIP(addr, hostName, "t1", "s1")
		if err != nil {
			panic(err)
		}
		log.Infof("Allocated %s for %s", ip, addr)
		if i > 4 {
			for j := 1; j <= 4; j++ {
				err = cl.IPAM.DeallocateIP(fmt.Sprintf("addr%d", j))
				if err != nil {
					panic(err)
				}
			}
			break
		}
		if i > 4 {
			break
		}

	}

}
