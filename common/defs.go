// Copyright (c) 2015 Pani Networks
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

package common

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Here we only keep type definitions and struct definitions with no behavior.

// Constants
const (
	// For passing in Gorilla Mux context the unmarshalled data
	ContextKeyUnmarshalledMap string = "UnmarshalledMap"
	// For passing in Gorilla Mux context path variables
	ContextKeyQueryVariables string = "QueryVars"
	// 	 For passing in Gorilla Mux context the original body data
	ContextKeyOriginalBody string = "OriginalBody"
	ContextKeyMarshaller   string = "Marshaller"
	ContextKeyRoles        string = "Roles"
	// DefaultRestTimeout, in milliseconds.
	DefaultRestTimeout    = 500
	DefaultRestRetries    = 3
	ReadWriteTimeoutDelta = 10

	// Name of the query parameter used for request token
	RequestTokenQueryParameter = "RequestToken"

	HeaderContentType = "content-type"

	Starting ServiceMessage = "Starting."

	// JSON
	TimeoutMessage = "{ \"error\" : \"Timed out\" }"

	// Empty string returned when there is a string return
	// but there is an error so no point in returning any
	// value.
	ErrorNoValue = ""

	// Path for authentication; if this is what is used
	// in the request we will not check the token (because
	// we are attempting to get a token at this point).
	AuthPath = "/auth"

	// Body provided.
	HookExecutableBodyArgument = "body"

	// Max port number for TCP/UDP
	MaxPortNumber = 65535
	MaxIcmpType   = 255
	
	ServiceRoot = "root"
	
)

type TokenMessage struct {
	Token string
}

// LinkResponse structure represents the commonly occurring
// {
//        "href" : "https://<own-addr>",
//        "rel"  : "self"
//  }
// part of the response.
type LinkResponse struct {
	Href string
	Rel  string
}

// Type definitions
type ServiceMessage string

// Struct definitions

// Message to register with the root service the actual
// port a service is listening on.
type PortUpdateMessage struct {
	Port uint64 `json:"port"`
}

type Endpoint struct {
	CidrStr string `json:"cidr,omitempty"`
	// TODO this can be collapsed into Cidr but needs
	// work on JSON marshaller/unmarshaller to do that.
	Cidr              net.IPNet `json:"-"`
	TenantID          uint64    `json:"tenant_id,omitempty"`
	TenantExternalID  string    `json:"tenant_external_id,omitempty"`
	TenantNetworkID   uint64    `json:"tenant_network_id,omitempty"`
	SegmentID         uint64    `json:"segment_id,omitempty"`
	SegmentExternalID string    `json:"segment_external_id,omitempty"`
	SegmentNetworkID  uint64    `json:"tenant_external_id,omitempty"`
}

const (
	PolicyDirectionIngress = "ingress"
	PolicyDirectionEgress  = "egress"
)

type PortRange [2]uint

func (p PortRange) String() string {
	return fmt.Sprintf("%d-%d", p[0], p[1])
}

type Rule struct {
	Protocol   string
	Ports      []uint
	PortRanges []PortRange
	// IcmpType only applies if Protocol value is ICMP and
	// is mutually exclusive with Ports or PortRanges
	IcmpType   uint
	IcmpCode   uint
	IsStateful bool
}

type Rules []Rule

// Metadata attached to entities for various external environments like Open Stack / Kubernetes
type Tag struct {
	Key   string
	Value string
}

// Policy describes Romana network security policy.
// For examples, see:
// 1. https://github.com/romana/core/blob/master/policy/policy.sample.json
// 2. https://github.com/romana/core/blob/master/policy/policy.example.agent.json
type Policy struct {
	// Direction is one of "ingress" or "egress"
	Direction string `json:"direction,omitempty"`
	// Description is human-redable description of the policy.
	Description string `json:"description,omitempty"`
	// Name is human-readable name for this policy.
	Name string `json:"name,omitempty"`
	// ID is Romana-generated unique (within Romana deployment) ID of this policy,
	// to be used in REST requests.
	ID uint64 `json:"id,omitempty",sql:"AUTO_INCREMENT"`
	// ExternalID is an optional identifier of this policy in an external system working
	// with Romana in this deployment (e.g., Open Stack).
	ExternalID string `json:"external_id,omitempty",sql:"not null;unique"`
	// Datacenter describes a Romana deployment.
	Datacenter Datacenter `json:"datacenter,omitempty"`
	AppliedTo  []Endpoint `json:"applied_to,omitempty"`
	Peers      []Endpoint `json:"peers,omitempty"`
	Rules      []Rule     `json:"rule,omitempty"`
	Tags       []Tag      `json:"tags,omitempty"`
}

// isValidProto checks if the Protocol specified in Rule is valid.
func isValidProto(proto string) bool {
	switch proto {
	case "icmp", "tcp", "udp":
		return true
	}
	return false
}

// Validate validates the policy and returns an error if the policy
// is invalid.
func (p *Policy) Validate() error {
	errMsg := ""
	p.Direction = strings.ToLower(p.Direction)
	if p.Direction != PolicyDirectionEgress && p.Direction != PolicyDirectionIngress {
		errMsg += fmt.Sprintf("Unknown direction '%s', allowed '%s' or '%s'. ", p.Direction, PolicyDirectionEgress, PolicyDirectionIngress)
	}
	for _, r := range p.Rules {
		r.Protocol = strings.ToLower(r.Protocol)
		if !isValidProto(r.Protocol) {
			errMsg += fmt.Sprintf("Invalid protocol %s. ", r.Protocol)
		}
		if r.Protocol == "tcp" {
			r.IsStateful = true
		}
		if r.Protocol == "tcp" || r.Protocol == "udp" {
			badRanges := make([]string, 0)
			for _, portRange := range r.PortRanges {
				if portRange[0] > portRange[1] || portRange[0] < 0 || portRange[1] < 0 || portRange[0] > MaxPortNumber || portRange[1] > MaxPortNumber {
					badRanges = append(badRanges, portRange.String())
				}
			}
			if len(badRanges) > 0 {
				errMsg += fmt.Sprintf("The following port ranges are invalid: %s. ", strings.Join(badRanges, ", "))
			}
			badPorts := make([]string, 0)
			for _, port := range r.Ports {
				if port < 0 || port > MaxPortNumber {
					badPorts = append(badPorts, string(port))
				}
			}
			if len(badPorts) > 0 {
				errMsg += fmt.Sprintf("The following ports are invalid: %s. ", strings.Join(badPorts, ", "))
			}
		}
		if r.Protocol == "icmp" {
			if r.IcmpCode > 0 || r.IcmpType > 0 {
				errMsg += "ICMP protocol is not specified but ICMP Code and/or ICMP Type are also specified. "
			} else {
				if len(r.Ports) > 0 || len(r.PortRanges) > 0 {
					errMsg += "ICMP protocol is specified but ports are also specified. "
				}
				if r.IcmpType < 0 || r.IcmpType > MaxIcmpType {
					errMsg += fmt.Sprintf("Invalid ICMP type: %d. ", r.IcmpType)
				}
				switch r.IcmpType {
				case 3: // Destination unreachable
					if r.IcmpCode < 0 || r.IcmpCode > 15 {
						errMsg += fmt.Sprintf("Invalid ICMP code for type %d: %d", r.IcmpType, r.IcmpCode)
					}
				case 4: // Source quench
					if r.IcmpCode != 0 {
						errMsg += fmt.Sprintf("Invalid ICMP code for type %d: %d", r.IcmpType, r.IcmpCode)
					}
				case 5: // Redirect
					if r.IcmpCode < 0 || r.IcmpCode > 3 {
						errMsg += fmt.Sprintf("Invalid ICMP code for type %d: %d", r.IcmpType, r.IcmpCode)
					}
				case 11: // Time exceeded
					if r.IcmpCode < 0 || r.IcmpCode > 1 {
						errMsg += fmt.Sprintf("Invalid ICMP code for type %d: %d", r.IcmpType, r.IcmpCode)
					}
				default:
					if r.IcmpCode != 0 {
						errMsg += fmt.Sprintf("Invalid ICMP code for type %d: %d", r.IcmpType, r.IcmpCode)
					}

				}
			}
		}
	}
	if errMsg == "" {
		return nil
	} else {
		return errors.New(errMsg)
	}
}

// RestServiceInfo describes information about a running
// Romana service.
type RestServiceInfo struct {
	// Address being listened on (as host:port)
	Address string
	// Channel to communicate with the service
	Channel chan ServiceMessage
}

// Response to /
type IndexResponse struct {
	ServiceName string `json:"serviceName"`
	Links       Links
}

// RootIndexResponse represents a response from the / path
// specific for root service only.
type RootIndexResponse struct {
	ServiceName string `json:"serviceName"`
	Links       Links
	Services    []ServiceResponse
}

// Service information
type ServiceResponse struct {
	Name  string
	Links Links
}

// Datacenter represents the configuration of a datacenter.
type Datacenter struct {
	Id        uint64 `sql:"AUTO_INCREMENT"`
	IpVersion uint   `json:"ip_version"`
	// We don't need to store this, but calculate and pass around
	Prefix      uint64 `json:"prefix"`
	Cidr        string
	PrefixBits  uint `json:"prefix_bits"`
	PortBits    uint `json:"port_bits"`
	TenantBits  uint `json:"tenant_bits"`
	SegmentBits uint `json:"segment_bits"`
	// We don't need to store this, but calculate and pass around
	EndpointBits      uint   `json:"endpoint_bits"`
	EndpointSpaceBits uint   `json:"endpoint_space_bits"`
	Name              string `json:"name"`
}
