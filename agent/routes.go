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

package agent

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/romana/core/common/api"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
)

// CreateRouteToBlocks loops over list of blocks and creates routes when needed.
func CreateRouteToBlocks(blocks []api.IPAMBlockResponse,
	hosts IpamHosts,
	romanaRouteTableId int,
	hostname string,
	multihop bool,
	nlHandle nlHandleRoute) {

	NumManagedRoutes.Set(float64(0))
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

		if err := createRouteToBlock(block, host, romanaRouteTableId, multihop, nlHandle); err != nil {
			_, ok := err.(RouteAdjacencyError)
			if ok {
				// Lower severity for expected error
				log.Tracef(4, "%s", err)
				continue
			}

			log.Errorf("%s", err)
			continue
		}
		NumManagedRoutes.Inc()
	}
}

type nlHandleRoute interface {
	RouteGet(net.IP) ([]netlink.Route, error)
	RouteAdd(*netlink.Route) error
}

// createRouteToBlock creates ip route for given block->host pair in Romana routing table,
// the function will fail if requested block is not directly adjacent and multihop false.
func createRouteToBlock(block api.IPAMBlockResponse, host *api.Host, romanaRouteTableId int, multihop bool, nlHandle nlHandleRoute) error {
	testRoutes, err := nlHandle.RouteGet(host.IP)
	if err != nil {
		return errors.Wrapf(err, "couldn't test host %s adjacency", host.IP)
	}

	if len(testRoutes) > 1 {
		return errors.New(fmt.Sprintf("more then one path available for host %s, multipath not currently supported", host.IP))
	}

	if len(testRoutes) == 0 {
		return errors.New(fmt.Sprintf("no way to reach %s, no default gateway?", host.IP))
	}

	if testRoutes[0].Gw != nil && multihop == false {
		return RouteAdjacencyError{}
	}

	route := netlink.Route{
		Dst:   &block.CIDR.IPNet,
		Gw:    host.IP,
		Table: romanaRouteTableId,
	}

	log.Debugf("About to create route %v", route)
	return nlHandle.RouteAdd(&route)
}

type RouteAdjacencyError struct{}

func (RouteAdjacencyError) Error() string {
	return "no directly adjacent route and multihop is prohibited"
}
