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
	"net"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/romana/core/common/api"
	"github.com/vishvananda/netlink"
)

type testHandle struct {
	rg []netlink.Route
	re error
}

func (h testHandle) RouteGet(ip net.IP) ([]netlink.Route, error) {
	return h.rg, h.re
}
func (h testHandle) RouteAdd(r *netlink.Route) error {
	return h.re
}

func TestCreateRouteToBlock(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("100.31.0.0/4")
	testBlock := api.IPAMBlockResponse{
		CIDR: api.IPNet{*ipnet},
	}

	cases := []struct {
		name, message string
		block         api.IPAMBlockResponse
		host          *api.Host
		multihop      bool
		testHandle    nlHandleRoute
		expect        func(error) bool
	}{
		{
			name:       "detect error when RouteGet() returns 0 results",
			message:    "failed to detect situation when RouteGet() returns 0 results",
			block:      testBlock,
			host:       &api.Host{IP: net.ParseIP("192.168.99.20")},
			multihop:   false,
			testHandle: testHandle{rg: nil},
			expect:     func(err error) bool { return strings.Contains(err.Error(), "no default gateway") },
		},
		{
			name:       "detect error when RouteGet() returns more then one result",
			message:    "failed to detect situation when RouteGet() returns more then one result",
			block:      testBlock,
			host:       &api.Host{},
			multihop:   false,
			testHandle: testHandle{rg: []netlink.Route{netlink.Route{}, netlink.Route{}}},
			expect:     func(err error) bool { return strings.Contains(err.Error(), "multipath not currently supported") },
		},
		{
			name:       "RouteGet() returns an error",
			message:    "failed to detect an error from RouteGet()",
			block:      testBlock,
			host:       &api.Host{},
			multihop:   false,
			testHandle: testHandle{re: errors.New("Dummy error")},
			expect:     func(err error) bool { return strings.Contains(err.Error(), "Dummy error") },
		},
		{
			name:       "detect fail with not adjacent block and multihop disabled",
			message:    "failed detect fail with not adjacent block and multihop disabled",
			block:      testBlock,
			host:       &api.Host{},
			multihop:   false,
			testHandle: testHandle{rg: []netlink.Route{netlink.Route{Gw: net.ParseIP("192.168.99.1")}}},
			expect:     func(err error) bool { _, ok := err.(RouteAdjacencyError); return ok },
		},
		{
			name:       "confirm success for nont adjacent block with multihop enabled",
			message:    "failed confirm success for nont adjacent block with multihop enabled",
			block:      testBlock,
			host:       &api.Host{},
			multihop:   true,
			testHandle: testHandle{re: nil, rg: []netlink.Route{netlink.Route{Gw: net.ParseIP("192.168.99.1")}}},
			expect:     func(err error) bool { return err == nil },
		},
		{
			name:       "confirm success for adjacent block without multihop",
			message:    "failed confirm success for adjacent block without multihop",
			block:      testBlock,
			host:       &api.Host{},
			multihop:   true,
			testHandle: testHandle{re: nil, rg: []netlink.Route{netlink.Route{Gw: nil}}},
			expect:     func(err error) bool { return err == nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := createRouteToBlock(tc.block, tc.host, 10, tc.multihop, tc.testHandle)
			if !tc.expect(err) {
				t.Fatalf("Result: %s, message: %s", err, tc.message)
			}
		})
	}
}
