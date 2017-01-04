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

package u32

import (
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
	return net.IP{}
}

func (m MockNC) PNetCIDR() (cidr *net.IPNet, err error) {
	return &net.IPNet{}, nil
}

func TestMatchDst(t *testing.T) {
	n := MockNC{uint(8), uint(8), uint(4), uint(4), uint(8)}
	addr := net.ParseIP("10.3.1.4")

	u := New(n)

	// Match destination address with net, tenant and segment bits of 10.3.1.4
	expression := u.Addr(addr).MatchNet().MatchTenant().MatchSegment().MatchDst()
	t.Logf("%s", expression)
	expected := "0x10&0xff00ff00=0xa000100"
	if expression != expected {
		t.Errorf("Unexpected u32 expression, expecting %s got %s", expected, expression)
	}

	// Match source address with host and endpoint bits of 10.3.1.4
	expression = u.Addr(addr).MatchHost().MatchEndpoint().MatchSrc()
	t.Logf("%s", u.Addr(addr).MatchHost().MatchEndpoint().MatchSrc())
	expected = "0xc&0xff00ff=0x30004"
	if expression != expected {
		t.Errorf("Unexpected u32 expression, expecting %s got %s", expected, expression)
	}

	u = New(n)

	t.Log("--------------------------------------------------------")
	// Match destination address with net=10, tenant=0 and segment=1
	expression = u.MatchNetId(uint(10)).MatchTenantId(uint(0)).MatchSegmentId(uint(1)).MatchDst()
	t.Logf("%s", expression)
	expected = "0x10&0xff00ff00=0xa000100"
	if expression != expected {
		t.Errorf("Unexpected u32 expression, expecting %s got %s", expected, expression)
	}

	u = New(n)

	// Match source address with host=3 and endpoint=4
	expression = u.MatchHostId(uint(3)).MatchEndpointId(uint(4)).MatchSrc()
	t.Logf("%s", expression)
	expected = "0xc&0xff00ff=0x30004"
	if expression != expected {
		t.Errorf("Unexpected u32 expression, expecting %s got %s", expected, expression)
	}
}
