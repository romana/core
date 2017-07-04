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
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"

	"github.com/vishvananda/netlink"
)

const (
	DefaultRouteTableId = 10
)

func main() {
	etcdEndpoints := flag.String("endpoints", "", "csv list of etcd endpoints to romana storage")
	etcdPrefix := flag.String("prefix", "", "string that prefixes all romana keys in etcd")
	hostname := flag.String("hostname", "", "name of the host in romana database")
	romanaRouteTableId := flag.Int("route-table-id", DefaultRouteTableId, "id that romana route table should have in /etc/iproute2/rt_tables")
	flag.Parse()

	romanaConfig := common.Config{
		EtcdEndpoints: strings.Split(*etcdEndpoints, ","),
		EtcdPrefix:    *etcdPrefix,
	}

	client, err := client.NewClient(&romanaConfig)
	if err != nil {
		panic(err)
	}

	err = ensureRouteTableExist(*romanaRouteTableId)
	if err != nil {
		panic(err)
	}

	err = ensureRomanaRouteRule(*romanaRouteTableId)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	blocksChannel := WatchBlocks(ctx, client)
	hostsChannel := WatchHosts(ctx, client)

	hosts := IpamHosts(client.ListHosts())
	for {
		select {
		case blocks := <-blocksChannel:
			err := flushRomanaTable()
			if err != nil {
				fmt.Printf("failed to flush romana route table err=(%s)", err)
				continue
			}

			for _, block := range blocks {
				if block.Host == *hostname {
					log.Printf("Block %v is local and does not require a route on that host", block)
					continue
				}

				host := hosts.GetHost(block.Host)
				if host == nil {
					log.Printf("Block %v belongs to unkonwn host %s, ignoring", block, block.Host)
					continue
				}

				if err := createRouteToBlock(block, host, *romanaRouteTableId); err != nil {
					log.Printf("%s", err)
				}
			}
		case newHosts := <-hostsChannel:
			// TODO need mutext for this.
			hosts = IpamHosts(newHosts)
		}
	}
}

// IpamHosts is a collection of hosts with search methods.
type IpamHosts []api.Host

func (hosts IpamHosts) GetHost(hostname string) *api.Host {
	/* this is disabled since current api.Host does not have `name` field.
	for hid, h := range hosts {
		if h.Name == hostname {
			return &hosts[hid]
		}
	}
	*/
	return nil
}

// createRouteToBlock creates ip route an the romana specific route table.
func createRouteToBlock(block api.IPAMBlockResponse, host *api.Host, romanaRouteTableId int) error {
	route := netlink.Route{
		Dst:   &block.CIDR.IPNet,
		Gw:    host.IP,
		Table: romanaRouteTableId,
	}

	var err error
	log.Printf("About to create route %v", route)
	// err := netlink.RouteAdd(&route)
	return err
}
