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

package cni

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type mockNlRouteHandle struct {
	linkByNameErr   error
	addRouteErr     error
	replaceRouteErr error
}

func (m mockNlRouteHandle) LinkByName(name string) (netlink.Link, error) {
	return &netlink.Device{}, m.linkByNameErr
}

func (m mockNlRouteHandle) RouteAdd(*netlink.Route) error {
	return m.addRouteErr
}

func (m mockNlRouteHandle) RouteReplace(*netlink.Route) error {
	return m.replaceRouteErr
}

func (m mockNlRouteHandle) Delete() {}

func (m mockNlRouteHandle) RouteGet(net.IP) ([]netlink.Route, error) {
	return []netlink.Route{}, nil
}

func TestAddEndpointRoute(t *testing.T) {
	dummyIpnet := &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff})}

	cases := []struct {
		name      string
		ifaceName string
		ip        *net.IPNet
		msg       string
		mock      mockNlRouteHandle
		test      func(error) bool
	}{
		{
			"detect failure during LinkByName",
			"dummy",
			dummyIpnet,
			"",
			mockNlRouteHandle{linkByNameErr: fmt.Errorf("bang")},
			func(err error) bool { return err.Error() == "bang" },
		},
		{
			"detect failure during route add",
			"dummy",
			dummyIpnet,
			"",
			mockNlRouteHandle{addRouteErr: fmt.Errorf("bang")},
			func(err error) bool { return strings.Contains(err.Error(), "couldn't create route") },
		},
		{
			"check switch to ReplaceRoute when unix.EEXIST",
			"dummy",
			dummyIpnet,
			"",
			mockNlRouteHandle{
				addRouteErr:     unix.EEXIST,
				replaceRouteErr: fmt.Errorf("bang"),
			},
			func(err error) bool { return strings.Contains(err.Error(), "couldn't replace route") },
		},
		{
			"check RouteAdd success",
			"dummy",
			dummyIpnet,
			"",
			mockNlRouteHandle{},
			func(err error) bool { return err == nil },
		},
		{
			"check switch to ReplaceRoute success",
			"dummy",
			dummyIpnet,
			"",
			mockNlRouteHandle{
				addRouteErr: unix.EEXIST,
			},
			func(err error) bool { return err == nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AddEndpointRoute(tc.ifaceName, tc.ip, tc.mock)
			if !tc.test(err) {
				t.Fatalf("%s, %s", tc.msg, err)
			}
		})
	}
}
