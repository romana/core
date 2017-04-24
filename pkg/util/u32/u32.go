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

// Package generates masks for u32 iptables module to match Romana entities.
package u32

import (
	"fmt"
	"github.com/romana/core/pkg/util/firewall"
	"math/big"
	"net"
)

// U32  provides facilities for generating expressions for iptables u32 module.
// The expressions can then be used to match romana entities
// encoded in an IP address.
type U32 struct {
	mask          *big.Int
	addr          *big.Int
	net           firewall.NetConfig
	matchNet      bool
	matchHost     bool
	matchTenant   bool
	matchSegment  bool
	matchEndpoint bool
}

// Creates new u32 facility
func New(net firewall.NetConfig) *U32 {
	u := &U32{mask: &big.Int{}, net: net}
	u.addr = big.NewInt(0)
	return u
}

// Pre loads u32 facility with an IP address. The address would be parsed and
// used as a source of romana bits for functions like u32.MatchHost().
// Note: Addr() is useful when user has an IP address and wants to
// generate an expression that matches parts of this address.
// If user wants to match arbitrary bits he should use u32.Match*Id(uint) functions.
func (u *U32) Addr(addr net.IP) *U32 {
	newAddr := big.NewInt(int64(0))
	newAddr.SetBytes([]byte(addr))
	u.addr = newAddr
	return u
}

// makeMask updates internal bitmask. That is it creates a new integer and for
// every bit of that integer that lies in a section defined by NetConfig and
// chosen by the user, it sets the bit to 1.
func (u *U32) makeMask() *U32 {
	u.mask = big.NewInt(int64(1))
	u.mask.Lsh(u.mask, 31)

	if u.matchNet {
		for i := 0; i < int(u.net.PrefixBits()); i++ {
			u.mask.SetBit(u.mask, u.mask.BitLen()-i-1, uint(1))
		}
	}

	if u.matchHost {
		position := int(u.net.PrefixBits()) + 1
		for i := 0; i < int(u.net.PortBits()); i++ {
			u.mask.SetBit(u.mask, u.mask.BitLen()-position-i, uint(1))
		}
	}

	if u.matchTenant {
		position := int(u.net.PrefixBits()) + int(u.net.PortBits()) + 1
		for i := 0; i < int(u.net.TenantBits()); i++ {
			u.mask.SetBit(u.mask, u.mask.BitLen()-position-i, uint(1))
		}
	}

	if u.matchSegment {
		position := int(u.net.PrefixBits()) + int(u.net.PortBits()) + int(u.net.TenantBits()) + 1
		for i := 0; i < int(u.net.SegmentBits()); i++ {
			u.mask.SetBit(u.mask, u.mask.BitLen()-position-i, uint(1))
		}
	}

	if u.matchEndpoint {
		position := int(u.net.PrefixBits()) + int(u.net.PortBits()) + int(u.net.TenantBits()) + int(u.net.SegmentBits()) + 1
		for i := 0; i < int(u.net.EndpointBits()); i++ {
			u.mask.SetBit(u.mask, u.mask.BitLen()-position-i, uint(1))
		}
	}

	if !u.matchNet {
		u.mask.SetBit(u.mask, u.mask.BitLen()-1, uint(0))
	}

	return u
}

// offset in an ip header, u32 going to examine 4 bits of the header starting from offset.
type offset int

const (
	// beginning of source IPv4 address in ip header.
	ip4src offset = 12

	// beginning of destination IPv4 address in ip header.
	ip4dst offset = 16
)

// makeMatch updates intenral mask and uses it to render u32 expression.
func (u *U32) makeMatch(d offset) string {
	u.makeMask()
	match := big.Int{}

	return fmt.Sprintf("0x%x&0x%x=0x%x", d, u.mask, match.And(u.mask, u.addr))
}

// MatchSrc renders u32 expression to match source IP address in IPv4 packet.
func (u *U32) MatchSrc() string {
	defer u.clearFlags()
	return u.makeMatch(ip4src)
}

// MatchDst renders u32 expression to match destination IP address in IPv4 packet.
func (u *U32) MatchDst() string {
	defer u.clearFlags()
	return u.makeMatch(ip4dst)
}

// MatchNet configures u32 facility to match Net bits of IP address provided by Addr() method.
func (u *U32) MatchNet() *U32 {
	u.matchNet = true
	return u
}

// MatchHost configures u32 facility to match Host bits of IP address provided by Addr() method.
func (u *U32) MatchHost() *U32 {
	u.matchHost = true
	return u
}

// MatchTenant configures u32 facility to match Tenant bits of IP address provided by Addr() method.
func (u *U32) MatchTenant() *U32 {
	u.matchTenant = true
	return u
}

// MatchSegment configures u32 facility to match Segment bits of IP address provided by Addr() method.
func (u *U32) MatchSegment() *U32 {
	u.matchSegment = true
	return u
}

// MatchEndpoint configures u32 facility to match Endpoint bits of IP address provided by Addr() method.
func (u *U32) MatchEndpoint() *U32 {
	u.matchEndpoint = true
	return u
}

// MatchEndpointId configures u32 facility to match provided value against Net bits of an address.
func (u *U32) MatchNetId(netId uint) *U32 {
	match := big.NewInt(int64(netId))
	match.Lsh(match, uint(32-int(u.net.PrefixBits())))
	u.addr = u.addr.Or(u.addr, match)

	u.matchNet = true

	return u
}

// MatchHostId configures u32 facility to match provided value against Host bits of an address.
func (u *U32) MatchHostId(hostId uint) *U32 {
	match := big.NewInt(int64(hostId))
	match.Lsh(match, uint(32-int(u.net.PrefixBits())-int(u.net.PortBits())))
	u.addr = u.addr.Or(u.addr, match)

	u.matchHost = true

	return u
}

// MatchTenantId configures u32 facility to match provided value against Tenant bits of an address.
func (u *U32) MatchTenantId(tenantId uint) *U32 {
	match := big.NewInt(int64(tenantId))
	match.Lsh(match, uint(32-int(u.net.PrefixBits())-int(u.net.PortBits())-int(u.net.TenantBits())))

	u.addr = u.addr.Or(u.addr, match)
	u.matchTenant = true

	return u
}

// MatchSegmentId configures u32 facility to match provided value against Segment bits of an address.
func (u *U32) MatchSegmentId(segmentId uint) *U32 {
	match := big.NewInt(int64(segmentId))
	match.Lsh(match, uint(32-int(u.net.PrefixBits())-int(u.net.PortBits())-int(u.net.TenantBits())-int(u.net.SegmentBits())))
	u.addr = u.addr.Or(u.addr, match)

	u.matchSegment = true

	return u
}

// MatchEndpointId configures u32 facility to match provided value against Endpoint bits of an address.
func (u *U32) MatchEndpointId(endpointId uint) *U32 {
	match := big.NewInt(int64(endpointId))
	// No need to shift endpoints
	u.addr = u.addr.Or(u.addr, match)

	u.matchEndpoint = true

	return u
}

// clearFlags clears configuration to allow reuse the facility.
func (u *U32) clearFlags() {
	u.matchNet = false
	u.matchHost = false
	u.matchTenant = false
	u.matchSegment = false
	u.matchEndpoint = false
}

// IPtoBig is a convinience method that produces big.Int from net.IP
func IPtoBig(ip net.IP) *big.Int {
	bigIP := big.NewInt(int64(0))
	bigIP.SetBytes([]byte(ip.To4()))

	return bigIP
}

// IPNETtoUint attempts to convert CIDR into uint which is useful for
// MatchNetId method
// It takes provided cidr e.g. "10.0.0.0/8" in net.IPnet format
// and shifts it to the right to produce 10 as uint.
// For example "100.112.0.0/12" converts to binary as
// Address:   100.112.0.0          01100100.0111 0000.00000000.00000000
// Netmask:   255.240.0.0 = 12     11111111.1111 0000.00000000.00000000
// this function will shift binary representation of the address to the
// right to preserving only bits protected by leading 1 in a netmask
// e.g. 01100100.0111 0000.00000000.00000000 >> 01100100.0111 = 1607
func IPNETtoUint(ipnet *net.IPNet) uint {

	maskLeadingOnes, maskSize := ipnet.Mask.Size()
	shift := maskSize - maskLeadingOnes

	bigIP := IPtoBig(ipnet.IP)
	bigIP = bigIP.Rsh(bigIP, uint(shift))

	return uint(bigIP.Int64())
}
