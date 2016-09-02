// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
//
// Code shared between firewall implementations

package firewall

import (
	"fmt"
	"net"
)

const (
	InputChainIndex      = 0
	OutputChainIndex     = 1
	ForwardInChainIndex  = 2
	ForwardOutChainIndex = 3

	targetDrop   = "DROP"
	targetAccept = "ACCEPT"

	iptablesCmd = "/sbin/iptables"

	ChainNameEndpointToHost  = "ROMANA-INPUT"
	ChainNameHostToEndpoint  = "ROMANA-FORWARD-IN"
	ChainNameEndpointEgress  = "ROMANA-FORWARD-OUT"
	ChainNameEndpointIngress = "ROMANA-FORWARD-IN"
)

// prepareU32Rules generates IPtables Rules for U32 iptables module.
// This Rules implemet Romana tenant/segment filtering
//   Return the filter Rules for the iptables u32 module.
//   Goal: Filter out any traffic that does not have the same tenant and segment
//   bits in the destination address as the interface itself.
//   These bits can be extracted from the IP address: This is the address that
//   we are assigning to the interface. The function is to be called when the
//   interface is set up. The passed-in address therefore can be trusted: It is
//   not taken from a packet.
//      Example:
//      ipAddr = "10.0.1.4"
//
//      Return:
//      filter = '12&0xFF00FF00=0xA000100&&16&0xFF00FF00=0xA000100'
//      chainPrefix = 'ROMANA-T0S1-'
//
//   TODO Refactor chain-prefix routine into separate function (prepareChainPrefix).
//   Also return the chain-prefix we'll use for this interface. This is
//   typically a string such as:
//       ROMANA-T<tenant-id>S<segment-id>-
//   For example, with tenant 1 and segment 2, this would be:
//       ROMANA-T1S2-
func prepareU32Rules(ipAddr net.IP, nc NetConfig) (string, string, error) {
	fullMask, err := prepareNetmaskBits(nc)
	if err != nil {
		return "", "", err
	}
	addr := ipToInt(ipAddr)
	if err != nil {
		return "", "", err
	}
	filter1 := fmt.Sprintf("0x%X=0x%X", fullMask, addr&fullMask)
	filter := fmt.Sprintf("12&%s&&16&%s", filter1, filter1)
	tenantID := extractTenantID(addr, nc)
	segmentID := extractSegmentID(addr, nc)
	chainPrefix := fmt.Sprintf("ROMANA-T%dS%d-", tenantID, segmentID)
	return filter, chainPrefix, nil
}

// prepareNetmaskBits returns integer representation of pseudo network bitmask.
// Used to prepare u32 firewall Rules that would match ip addresses belonging
// to given tenant/segment pair.
func prepareNetmaskBits(nc NetConfig) (uint64, error) {
	iCidrMask, err := PseudoNetNetmaskInt(nc)
	if err != nil {
		return 0, err
	}
	combinedTSMask := prepareTenantSegmentMask(nc)
	res := iCidrMask | combinedTSMask
	return res, nil
}

// PseudoNetNetmaskInt returns integer representation of pseudo net netmask.
func PseudoNetNetmaskInt(nc NetConfig) (uint64, error) {
	cidr, err := nc.PNetCIDR()
	if err != nil {
		return 0, err
	}
	pNetMaskInt, err := MaskToInt(cidr.Mask)
	if err != nil {
		return 0, err
	}
	return pNetMaskInt, nil
}

// prepareTenantSegmentMask returns integer representation of a bitmask
// for tenant+segment bits in pseudo network.
func prepareTenantSegmentMask(nc NetConfig) uint64 {
	var res uint64
	tenantBits := nc.TenantBits()
	segmentBits := nc.SegmentBits()
	combinedTSBits := tenantBits + segmentBits
	endpointBits := nc.EndpointBits()
	res = ((1 << combinedTSBits) - 1) << endpointBits
	return res
}

// extractSegmentID extracts segment id from the given ip address.
// This is possible because segment id encoded in the ip address.
func extractSegmentID(addr uint64, nc NetConfig) uint64 {
	endpointBits := nc.EndpointBits()
	segmentBits := nc.SegmentBits()
	sid := (addr >> endpointBits) & ((1 << segmentBits) - 1)
	return sid
}

// extractTenantID extracts tenant id from given the ip address.
// This is possible because tenant id encoded in the ip address.
func extractTenantID(addr uint64, nc NetConfig) uint64 {
	endpointBits := nc.EndpointBits()
	segmentBits := nc.SegmentBits()
	tenantBits := nc.TenantBits()
	tid := (addr >> (endpointBits + segmentBits)) & ((1 << tenantBits) - 1)
	return tid
}
