// Copyright (c) 2016 Pani Networks
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
	"github.com/romana/core/pkg/util/iptsave"
	"github.com/romana/core/tenant"
	"net"
	"testing"
)

type MockNC struct {
	netBits      uint
	portBits     uint
	tenantBits   uint
	segmentBits  uint
	endpointBits uint
}

func (m MockNC) PrefixBits() uint {
	return m.netBits
}

func (m MockNC) PortBits() uint {
	return m.portBits
}

func (m MockNC) TenantBits() uint {
	return m.tenantBits
}

func (m MockNC) SegmentBits() uint {
	return m.segmentBits
}

func (m MockNC) EndpointBits() uint {
	return m.endpointBits
}

func (m MockNC) EndpointNetmaskSize() uint64 {
	return uint64(0)
}

func (m MockNC) RomanaGW() net.IP {
	return net.ParseIP("10.0.0.1")
}

func (m MockNC) PNetCIDR() (cidr *net.IPNet, err error) {
	return &net.IPNet{}, nil
}

func TestMakeIngressTenantJumpRule(t *testing.T) {
	netConfig := MockNC{uint(8), uint(8), uint(4), uint(4), uint(8)}
	rule := MakeIngressTenantJumpRule(tenant.Tenant{NetworkID: uint64(2)}, netConfig)
	t.Log(rule)
}

func makeMockRule(body string, target string) *iptsave.IPrule {
	return &iptsave.IPrule{
		Match: []*iptsave.Match{
			&iptsave.Match{
				Body: body,
			},
		},
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionDefault,
			Body: target,
		},
	}
}

func TestInsertNormalRule(t *testing.T) {
	fakeChain := &iptsave.IPchain{
		Name: "Test",
		Rules: []*iptsave.IPrule{
			makeMockRule("Header Rule 1", "ACCEPT"),
			makeMockRule("Header Rule 2", "ACCEPT"),
			makeMockRule("Footer Rule 1", "RETURN"),
			makeMockRule("Footer Rule 2", "DROP"),
		},
	}

	InsertNormalRule(fakeChain, makeMockRule("Normal Rule 1", "LOG"))
	if fakeChain.Rules[2].Action.Body != "LOG" {
		t.Errorf("Unexpected rule at first normal position, expect LOG got %s", fakeChain.Rules[2])
	}
	t.Logf("%s", fakeChain)

	fakeChain = &iptsave.IPchain{
		Name: "Test",
		Rules: []*iptsave.IPrule{
			makeMockRule("Footer Rule 1", "RETURN"),
			makeMockRule("Footer Rule 2", "DROP"),
		},
	}

	InsertNormalRule(fakeChain, makeMockRule("Normal Rule 1", "LOG"))
	if fakeChain.Rules[0].Action.Body != "LOG" {
		t.Errorf("Unexpected rule at first normal position, expect LOG got %s", fakeChain.Rules[0])
	}
	t.Logf("%s", fakeChain)

	fakeChain = &iptsave.IPchain{
		Name: "Test",
		Rules: []*iptsave.IPrule{
			makeMockRule("Header Rule 1", "ACCEPT"),
			makeMockRule("Header Rule 2", "ACCEPT"),
		},
	}

	InsertNormalRule(fakeChain, makeMockRule("Normal Rule 1", "LOG"))
	if fakeChain.Rules[2].Action.Body != "LOG" {
		t.Errorf("Unexpected rule at first normal position, expect LOG got %s", fakeChain.Rules[2])
	}
	t.Logf("%s", fakeChain)

}
