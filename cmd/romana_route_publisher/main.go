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

package main

import (
	"flag"
	"os"
	"strings"
	"time"

	"github.com/romana/core/agent/router/bird"
	"github.com/romana/core/agent/router/publisher"
	"github.com/romana/core/common"
	"github.com/romana/core/common/client"
	log "github.com/romana/rlog"
)

// GetGroupByHost finds all groups on IPAM which have host with given hostname,
// returns map[NetworkName]Group. If host not found in any group of a network
// then the network isn't mentioned in return map.
func GetGroupByHost(ipam *client.IPAM, hostname string) map[string]*client.Group {

	hostInList := func(hosts []*client.Host, hostname string) bool {
		for _, host := range hosts {
			if host.Name == hostname {
				return true
			}
		}

		return false
	}

	// hostInGroup is a recursive function, currently in Go anonymous functions
	// can't be recursive, which is why this variable exists to make the function
	// _less_ anonymous.
	var hostInGroup func(group *client.Group, hostname string) *client.Group

	hostInGroup = func(group *client.Group, hostname string) *client.Group {
		if hostInList(group.Hosts, hostname) {
			return group
		}

		if group.Groups == nil {
			return nil
		}

		for _, nestedGroup := range group.Groups {
			g := hostInGroup(nestedGroup, hostname)
			if g != nil {
				return g
			}
		}

		return nil
	}

	res := make(map[string]*client.Group)

	for netName, net := range ipam.Networks {
		group := hostInGroup(net.Group, hostname)
		if group != nil {
			res[netName] = group
		}
	}

	return res
}

func main() {
	var err error

	etcdEndpoints := flag.String("endpoints", "", "csv list of etcd endpoints to romana storage")
	etcdPrefix := flag.String("prefix", "", "string that prefixes all romana keys in etcd")
	hostname := flag.String("hostname", "", "name of the host in romana database")
	flagTemplateFile := flag.String("template", "/etc/bird/bird.conf.t", "template file for bird config")
	flagBirdConfigFile := flag.String("config", "/etc/bird/bird.conf", "location of the bird config file")
	flagBirdPidFile := flag.String("pid", "/var/run/bird.pid", "location of bird pid file")
	flagDebug := flag.String("debug", "", "set to yes or true to enable debug output")
	flagLocalAS := flag.String("as", "65534", "local as number")
	flag.Parse()

	config := make(map[string]string)
	config["templateFileName"] = *flagTemplateFile
	config["birdConfigName"] = *flagBirdConfigFile
	config["pidFile"] = *flagBirdPidFile
	config["localAS"] = *flagLocalAS
	config["debug"] = *flagDebug

	bird, err := bird.New(publisher.Config(config))
	if err != nil {
		panic(err)
	}

	romanaConfig := common.Config{
		EtcdEndpoints: strings.Split(*etcdEndpoints, ","),
		EtcdPrefix:    *etcdPrefix,
	}

	if *hostname == "" {
		*hostname, err = os.Hostname()
		if err != nil {
			panic(err)
		}
	}

	romanaClient, err := client.NewClient(&romanaConfig)
	if err != nil {
		log.Errorf("Failed to initialize romana client: %v", err)
		os.Exit(2)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	// blocksChannel := WatchBlocks(ctx, romanaClient)
	blocksChannel, err := romanaClient.WatchBlocks(stopCh)
	if err != nil {
		log.Errorf("Failed to start watching for blocks, %s", err)
		os.Exit(2)
	}

	for {
		select {
		case blocks := <-blocksChannel:
			startTime := time.Now()

			hostGroups := GetGroupByHost(romanaClient.IPAM, *hostname)
			args := make(map[string]interface{})

			if len(hostGroups) > 0 {
				args["HostGroups"] = hostGroups
			}

			createRouteToBlocks(blocks.Blocks, args, *hostname, bird)
			runTime := time.Now().Sub(startTime)
			log.Tracef(4, "Time between route table flush and route table rebuild %s", runTime)

		}
	}
}
