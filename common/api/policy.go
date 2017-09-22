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

package api

import (
	"fmt"

	"github.com/romana/core/common"
)

const (
	// Max port number for TCP/UDP.
	MaxPortNumber = 65535
	MaxIcmpType   = 255

	// Wildcard
	Wildcard = "any"
)

// Endpoint represents an endpoint - that is, something that
// has an IP address and routes to/from. It can be a container,
// a Kubernetes POD, a VM, etc.
type Endpoint struct {
	Peer      string `json:"peer,omitempty"`
	Cidr      string `json:"cidr,omitempty"`
	Dest      string `json:"dest,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	SegmentID string `json:"segment_id,omitempty"`
}

func (e Endpoint) String() string {
	return common.String(e)
}

const (
	PolicyDirectionIngress = "ingress"
	PolicyDirectionEgress  = "egress"
)

type PortRange [2]uint

func (p PortRange) String() string {
	return fmt.Sprintf("%d-%d", p[0], p[1])
}

// Rule describes a rule of the policy. The following requirements apply
// (the policy would not be validated otherwise):
// 1. Protocol must be specified.
// 2. Protocol must be one of those validated by isValidProto().
// 3. Ports cannot be negative or greater than 65535.
// 4. If Protocol specified is "icmp", Ports and PortRanges fields should be blank.
// 5. If Protocol specified is not "icmp", Icmptype and IcmpCode should be unspecified.
type Rule struct {
	Protocol   string      `json:"protocol,omitempty"`
	Ports      []uint      `json:"ports,omitempty"`
	PortRanges []PortRange `json:"port_ranges,omitempty"`
	// IcmpType only applies if Protocol value is ICMP and
	// is mutually exclusive with Ports or PortRanges
	IcmpType   uint `json:"icmp_type,omitempty"`
	IcmpCode   uint `json:"icmp_code,omitempty"`
	IsStateful bool `json:"is_stateful,omitempty"`
}

func (r Rule) String() string {
	return common.String(r)
}

type Rules []Rule

// Metadata attached to entities for various external environments like Open Stack / Kubernetes
type Tag struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// Policy describes Romana network security policy.
// For examples, see:
// 1. https://github.com/romana/core/blob/master/policy/policy.sample.json
// 2. https://github.com/romana/core/blob/master/policy/policy.example.agent.json
type Policy struct {
	ID string `json:"id"`
	// Direction is one of common.PolicyDirectionIngress or common.PolicyDirectionIngress,
	// otherwise common.Validate will return an error.
	Direction string `json:"direction,omitempty" romana:"desc:Direction is one of 'ingress' or egress'."`
	// Description is human-redable description of the policy.
	Description string `json:"description,omitempty"`
	// Datacenter describes a Romana deployment.
	AppliedTo []Endpoint      `json:"applied_to,omitempty"`
	Ingress   []RomanaIngress `json:"ingress,omitempty"`
	//	Tags       []Tag      `json:"tags,omitempty"`
}

type RomanaIngress struct {
	Peers []Endpoint `json:"peers,omitempty"`
	Rules []Rule     `json:"rules,omitempty"`
}

func (p Policy) String() string {
	return common.String(p)
}
