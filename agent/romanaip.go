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
	"errors"
	"fmt"
	"syscall"

	"github.com/romana/core/common"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
)

func (a *Agent) linkAddIP(ip string) error {
	ipAddress, err := netlink.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("Error parsing IP Address: %s", err)
	}
	return netlink.AddrAdd(a.defaultLink, ipAddress)
}

func (a *Agent) linkDelIP(ip string) error {
	ipAddress, err := netlink.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("Error parsing IP Address: %s", err)
	}
	return netlink.AddrDel(a.defaultLink, ipAddress)
}

func (a *Agent) getDefaultLink() (netlink.Link, error) {
	defaultR := netlink.Route{}

	routes, err := netlink.RouteList(nil, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("Error finding default route: %s", err)
	}

	for _, r := range routes {
        // If dst/src is not specified for a route, then it
        // means a default route is found which handles packets
        // for everything which is not handled by specific routes.
		if r.Src == nil && r.Dst == nil {
			defaultR = r
			break
		}
	}

	link, err := netlink.LinkByIndex(defaultR.LinkIndex)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, errors.New("Error, could not locate default link for host")
	}

	return link, nil
}

func (a *Agent) romanaIPPostHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	ip := input.(*string)

	log.Infof("Agent: received romanaIP for addition %s\n", ip)

	err := a.linkAddIP(*ip)
	if err != nil {
		return nil, err
	}

	return "OK", nil
}

func (a *Agent) romanaIPDeleteHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	ip := input.(*string)

	log.Infof("Agent: received romanaIP for deletion %s\n", ip)

	err := a.linkDelIP(*ip)
	if err != nil {
		return nil, err
	}

	return "OK", nil
}
