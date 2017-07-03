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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package api

import (
	"log"
	"testing"
)

// TestPolicyValidation tests Validate method of Policy.
func TestPolicyValidation(t *testing.T) {
	goodAppliedTo := []Endpoint{Endpoint{TenantID: uint64(33)}}

	// 1. Test validation of port ranges
	badPorts := make([]uint, 2)
	badPorts[0] = 65536
	badPorts[1] = 100000
	badPortRanges := make([]PortRange, 2)
	badPortRanges[0] = PortRange{3, 65536}
	badPortRanges[1] = PortRange{10, 4}
	rules := Rules{
		Rule{Ports: badPorts, Protocol: "tcp"},
		Rule{PortRanges: badPortRanges, Protocol: "udp"},
	}

	// 2. Test no applied to
	policy := Policy{
		Ingress: []RomanaIngress{
			RomanaIngress{Rules: rules},
		},
		Direction: PolicyDirectionEgress}
	err := policy.Validate()
	if err == nil {
		t.Error("Unexpected nil")
	}
	err2 := err.(HttpError)
	log.Printf("Bad ports/ranges: %v", err2)
	det := (err2.Details).([]string)
	expect(t, det[1], "Rule #1: The following ports are invalid: 65536, 100000.")
	expect(t, det[2], "Rule #2: The following port ranges are invalid: 3-65536, 10-4.")
	expect(t, det[0], "Required 'applied_to' entry missing.")

	policy = Policy{
		Ingress: []RomanaIngress{
			RomanaIngress{Rules: rules},
		},
		Direction: PolicyDirectionEgress,
		AppliedTo: goodAppliedTo}
	err = policy.Validate()
	if err == nil {
		t.Error("Unexpected nil")
	}
	err2 = err.(HttpError)
	log.Printf("Bad ports/ranges: %v", err2)
	det = (err2.Details).([]string)
	expect(t, det[0], "Rule #1: The following ports are invalid: 65536, 100000.")
	expect(t, det[1], "Rule #2: The following port ranges are invalid: 3-65536, 10-4.")

	// 2. Test bad protocols and direction
	rules = Rules{
		Rule{},
		Rule{Protocol: "xxxx"},
	}
	policy = Policy{
		Ingress: []RomanaIngress{
			RomanaIngress{Rules: rules},
		},
		Direction: "bla",
		AppliedTo: goodAppliedTo}
	err = policy.Validate()
	if err == nil {
		t.Error("Unexpected nil")
	}
	err2 = err.(HttpError)
	log.Printf("Bad direction/protocol: %v", err2)
	det = (err2.Details).([]string)
	expect(t, det[0], "Unknown direction 'bla', allowed 'egress' or 'ingress'.")
	expect(t, det[1], "Rule #1: No protocol specified.")
	expect(t, det[2], "Rule #2: Invalid protocol: xxxx.")

	// 4. Test mismatch of proto and ports
	rules = Rules{
		Rule{Ports: []uint{10, 40}, Protocol: "icmp"},
		Rule{IcmpType: 1, Protocol: "udp"},
		Rule{IcmpType: 3, IcmpCode: 33, Protocol: "icmp"},
	}
	policy = Policy{
		Ingress: []RomanaIngress{
			RomanaIngress{Rules: rules},
		},
		Direction: PolicyDirectionEgress,
		AppliedTo: goodAppliedTo}
	err = policy.Validate()
	if err == nil {
		t.Error("Unexpected nil")
	}
	err2 = err.(HttpError)
	log.Printf("Bad proto/ports: %v", err2)
	det = (err2.Details).([]string)
	expect(t, det[0], "Rule #1: ICMP protocol is specified but ports are also specified.")
	expect(t, det[1], "Rule #2: ICMP protocol is not specified but ICMP Code and/or ICMP Type are also specified.")
	expect(t, det[2], "Rule #3: Invalid ICMP code for type 3: 33.")

	// 5. Test tenant ID in applied.
	rules = Rules{
		Rule{Ports: []uint{10, 40}, Protocol: "tcp"},
	}
	badAppliedTo := []Endpoint{
		Endpoint{TenantID: uint64(33)},
		Endpoint{},
	}
	policy = Policy{
		Ingress: []RomanaIngress{
			RomanaIngress{Rules: rules},
		},
		Direction: PolicyDirectionEgress,
		AppliedTo: badAppliedTo}
	err = policy.Validate()
	if err == nil {
		t.Error("Unexpected nil")
	}
	err2 = err.(HttpError)
	log.Printf("Bad tenant: %v", err2)
	det = (err2.Details).([]string)
	expect(t, det[0], "applied_to entry #2: at least one of: dest, tenant, tenant_id, tenant_external_id or tenant_network_id must be specified.")
}
