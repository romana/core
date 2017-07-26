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

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
	log "github.com/romana/rlog"

	"github.com/vishvananda/netlink"
)

const (
	DefaultRouteTableId = 10
	DefaultGwIP         = "127.42.0.1"
)

func main() {
	var err error

	etcdEndpoints := flag.String("endpoints", "", "csv list of etcd endpoints to romana storage")
	etcdPrefix := flag.String("prefix", "", "string that prefixes all romana keys in etcd")
	hostname := flag.String("hostname", "", "name of the host in romana database")
	provisionIface := flag.Bool("provision-iface", false, "create romana-gw interface and ip")
	provisionSysctls := flag.Bool("provision-sysctls", false, "configure routing sysctls")
	romanaRouteTableId := flag.Int("route-table-id", DefaultRouteTableId,
		"id that romana route table should have in /etc/iproute2/rt_tables")
	mock := flag.Bool("mock", false, "")
	flag.Parse()

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

	var romanaClient RomanaClient
	if *mock {
		romanaClient = MockClient{}
	} else {

		rClient, err := client.NewClient(&romanaConfig)
		if err != nil {
			log.Errorf("Failed to create Romana client, %s. Unable to continue", err.Error())
			os.Exit(2)
		}

		romanaClient = RomanaClientAdaptor{rClient}

	}

	if *provisionIface {
		err := CreateRomanaGW()
		if err != nil {
			log.Errorf("Failed to create romana-gw interface. %s", err)
			os.Exit(2)
		}

		err = SetRomanaGwIP(DefaultGwIP)
		if err != nil {
			log.Errorf("Failed to install ip address on romana-gw interface. %s", err)
			os.Exit(2)
		}

	}

	if *provisionSysctls {
		err := ProvisionSysctls()
		if err != nil {
			log.Errorf("Failed to provision systls %s", err)
			os.Exit(2)
		}
	}

	err = ensureRouteTableExist(*romanaRouteTableId)
	if err != nil {
		log.Errorf("Failed to make `romana` alias for route table=%d, %s. Unable to continue", *romanaRouteTableId, err.Error())
		os.Exit(2)
	}

	err = ensureRomanaRouteRule(*romanaRouteTableId)
	if err != nil {
		log.Errorf("Failed to install route rule for romana routing table, %s", err.Error())
		os.Exit(2)
	}

	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()

	stopCh := make(chan struct{})
	defer close(stopCh)

	// blocksChannel := WatchBlocks(ctx, romanaClient)
	blocksChannel, err := romanaClient.WatchBlocks(stopCh)
	if err != nil {
		log.Errorf("Failed to start watching for blocks, %s", err)
		os.Exit(2)
	}
	// hostsChannel := WatchHosts(ctx, romanaClient)
	hostsChannel, err := romanaClient.WatchHosts(stopCh)
	if err != nil {
		log.Errorf("Failed to start watching for blocks, %s", err)
		os.Exit(2)
	}

	hosts := IpamHosts(romanaClient.ListHosts().Hosts)
	for {
		select {
		case blocks := <-blocksChannel:
			err := flushRomanaTable()
			if err != nil {
				log.Errorf("failed to flush romana route table err=(%s)", err)
				continue
			}

			createRouteToBlocks(blocks.Blocks, hosts, *romanaRouteTableId, *hostname)

		case newHosts := <-hostsChannel:
			// TODO need mutex for this.
			hosts = IpamHosts(newHosts.Hosts)
		}
	}
}

// IpamHosts is a collection of hosts with search methods.
type IpamHosts []api.Host

func (hosts IpamHosts) GetHost(hostname string) *api.Host {
	for hid, h := range hosts {
		if h.Name == hostname {
			return &hosts[hid]
		}
	}
	return nil
}

// createRouteToBlocks loops over list of blocks and creates routes when needed.
func createRouteToBlocks(blocks []api.IPAMBlockResponse, hosts IpamHosts, romanaRouteTableId int, hostname string) {
	for _, block := range blocks {
		if block.Host == hostname {
			log.Errorf("Block %v is local and does not require a route on that host", block)
			continue
		}

		host := hosts.GetHost(block.Host)
		if host == nil {
			log.Errorf("Block %v belongs to unknown host %s, ignoring", block, block.Host)
			continue
		}

		if err := createRouteToBlock(block, host, romanaRouteTableId); err != nil {
			log.Errorf("%s", err)
		}
	}
}

// createRouteToBlock creates ip route for given block->host pair in Romana routing table.
func createRouteToBlock(block api.IPAMBlockResponse, host *api.Host, romanaRouteTableId int) error {
	route := netlink.Route{
		Dst:   &block.CIDR.IPNet,
		Gw:    host.IP,
		Table: romanaRouteTableId,
	}

	var err error
	log.Debugf("About to create route %v", route)
	err = netlink.RouteAdd(&route)
	return err
}
