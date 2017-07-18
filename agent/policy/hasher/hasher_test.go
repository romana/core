// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package hasher

import (
	"testing"

	"github.com/romana/core/common"
)

func TestNewEndpointList(t *testing.T) {

	endpointList := []common.Endpoint{
		common.Endpoint{
			Peer: "Foo",
			Dest: "Bar",
		},
		common.Endpoint{
			TenantName:      "alice",
			TenantNetworkID: nil,
		},
		common.Endpoint{
			Peer: "Dead",
			Dest: "Beef",
		},
	}

	t.Logf("Before sort %v", endpointList)
	newList := NewEndpointList(endpointList).Sort().List()
	t.Logf("After sort %v", newList)

	if newList[2].Peer != "Foo" {
		t.Errorf("Unexpected result from NewEndpointList, %v", newList)
	}
}

func TestSortRules(t *testing.T) {
	ruleList := []common.Rule{
		common.Rule{
			Protocol: "TCP",
			Ports:    []uint{1, 2, 3},
		},
		common.Rule{
			Protocol: "ICMP",
			IcmpType: uint(7),
			IcmpCode: uint(8),
		},
		common.Rule{
			Protocol: "TCP",
			PortRanges: []common.PortRange{
				common.PortRange{0, 9},
				common.PortRange{8, 2},
			},
		},
		common.Rule{
			Protocol: "UDP",
			Ports:    []uint{6, 5, 4},
		},
	}

	t.Logf("Before sort %v", ruleList)
	newList := RulesToCanonical(ruleList)
	t.Logf("After sort %v", newList)

	if newList[3].Ports[2] != 6 {
		t.Errorf("Unexpected result from SortRules, %v", newList)
	}
}

func TestHashRomanaPolicies(t *testing.T) {
	policyList := []common.Policy{
		common.Policy{
			Direction:   "ingress",
			Description: "test policy one",
			Name:        "one",
			ExternalID:  "foo",
			AppliedTo: []common.Endpoint{
				common.Endpoint{
					Peer: "Host",
					Dest: "Local",
				},
			},
			Ingress: []common.RomanaIngress{
				common.RomanaIngress{
					Peers: []common.Endpoint{
						common.Endpoint{
							TenantName:  "Alice",
							SegmentName: "AliceVille",
						},
					},
					Rules: []common.Rule{
						common.Rule{
							Protocol: "TCP",
							Ports:    []uint{5, 4, 3},
						},
					},
				},
			},
		},
		common.Policy{
			Direction:   "ingress",
			Description: "test policy two",
			Name:        "two",
			ExternalID:  "bar",
			AppliedTo: []common.Endpoint{
				common.Endpoint{
					Peer: "Local",
					Dest: "Host",
				},
			},
			Ingress: []common.RomanaIngress{
				common.RomanaIngress{
					Peers: []common.Endpoint{
						common.Endpoint{
							TenantName:  "Bob",
							SegmentName: "BobHold",
						},
					},
					Rules: []common.Rule{
						common.Rule{
							Protocol: "TCP",
							Ports:    []uint{9, 8, 7},
						},
					},
				},
			},
		},
	}

	hash := HashRomanaPolicies(policyList)
	if hash != "fcfe27cb94edeb6cdb186192ed32e1c83374d3a5" {
		t.Errorf("Unexpected result from HashRomanaPolicies %s", hash)
	} else {
		t.Logf("Hash is %s", hash)
	}
}
