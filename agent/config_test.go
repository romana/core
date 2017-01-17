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

// package agent's this file contains all the necessary functions
// to bring up romana gateway, update necessary kernel parameters
// and then finally update routes needed by romana to successfully
// communicate between nodes in romana cluster.
package agent

import (
	"fmt"
	"net"
	"reflect"
	"testing"
)

type testcidrs struct {
	cidr    *net.IPNet
	firstIP string
}

var tests = []testcidrs{
	{
		cidr: &net.IPNet{IP: net.IPv4(192, 168, 0, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0)},
		firstIP: "192.168.0.1/24",
	},
	{
		cidr: &net.IPNet{IP: net.IPv4(10, 0, 0, 1),
			Mask: net.IPv4Mask(255, 0, 0, 0)},
		firstIP: "10.0.0.1/8",
	},
	{
		cidr: &net.IPNet{IP: net.IPv4(172, 16, 0, 128),
			Mask: net.IPv4Mask(255, 255, 255, 128)},
		firstIP: "172.16.0.129/25",
	},
}

func TestGetFirstIPinCIDR(t *testing.T) {
	// Negative test cases
	v, err := GetFirstIPinCIDR(nil)
	if v != nil || !reflect.DeepEqual(
		fmt.Errorf("Agent Error, no input provided to GetFirstIPinCIDR"), err) {
		t.Error("Expected: <nil>", " got: ", v, "error: ", err)
	}

	v, err = GetFirstIPinCIDR(&net.IPNet{})
	if v != nil || !reflect.DeepEqual(
		fmt.Errorf("Agent Error, invalid IP/Mask provided to GetFirstIPinCIDR"), err) {
		t.Error("Expected: <nil>", " got: ", v, "error: ", err)
	}

	ip := &net.IPNet{IP: net.IPv4(172, 16, 0, 1),
		Mask: net.IPv4Mask(255, 255, 255, 255)}
	v, err = GetFirstIPinCIDR(ip)
	if v != nil || err == nil {
		t.Error("Expected an error, got no error")
	}

	// Positive test cases
	for _, c := range tests {
		v, err := GetFirstIPinCIDR(c.cidr)
		if v.String() != c.firstIP {
			t.Error("Expected: ", c.firstIP, " got: ", v, "error: ", err)
		}
	}
}
