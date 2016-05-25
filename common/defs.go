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

// Definitions of common structures.

import (
	"fmt"
	"net"
	"strings"
	"time"
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

	// Max port number for TCP/UDP.
	MaxPortNumber = 65535
	MaxIcmpType   = 255

	// Wildcard
	Wildcard = "any"
	// Name of root service
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
	Any     string `json:"any,omitempty"`
	Peer    string `json:"peer,omitempty"`
	CidrStr string `json:"cidr,omitempty"`
	// TODO this can be collapsed into Cidr but needs
	// work on JSON marshaller/unmarshaller to do that.
	Cidr              net.IPNet `json:"-"`
	TenantID          uint64    `json:"tenant_id,omitempty"`
	TenantExternalID  string    `json:"tenant_external_id,omitempty"`
	TenantNetworkID   uint64    `json:"tenant_network_id,omitempty"`
	SegmentID         uint64    `json:"segment_id,omitempty"`
	SegmentExternalID string    `json:"segment_external_id,omitempty"`
	SegmentNetworkID  uint64    `json:"segment_network_id,omitempty"`
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
	Protocol   string      `json:"protocol"`
	Ports      []uint      `json:"ports,omitempty"`
	PortRanges []PortRange `json:"port_ranges,omitempty"`
	// IcmpType only applies if Protocol value is ICMP and
	// is mutually exclusive with Ports or PortRanges
	IcmpType   uint `json:"icmp_type,omitempty"`
	IcmpCode   uint `json:"icmp_code,omitempty"`
	IsStateful bool `json:"is_stateful,omitempty"`
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
	// Direction is one of common.PolicyDirectionIngress or common.PolicyDirectionIngress,
	// otherwise common.Validate will return an error.
	Direction string `json:"direction,omitempty"`
	// Description is human-redable description of the policy.
	Description string `json:"description,omitempty"`
	// Name is human-readable name for this policy.
	Name string `json:"name"`
	// ID is Romana-generated unique (within Romana deployment) ID of this policy,
	// to be used in REST requests. It will be ignored when set by user.
	ID uint64 `json:"id,omitempty",sql:"AUTO_INCREMENT"`
	// ExternalID is an optional identifier of this policy in an external system working
	// with Romana in this deployment (e.g., Open Stack).
	ExternalID string `json:"external_id,omitempty",sql:"not null;unique"`
	// Datacenter describes a Romana deployment.
	Datacenter Datacenter `json:"datacenter,omitempty"`
	AppliedTo  []Endpoint `json:"applied_to,omitempty"`
	Peers      []Endpoint `json:"peers,omitempty"`
	Rules      []Rule     `json:"rules,omitempty"`
	//	Tags       []Tag      `json:"tags,omitempty"`
}

// PolicyDb represents how common.Policy is stored in the database.
// For now to keep it simple, it will not be fully normalized --
// we will just keep an ID and policy document as JSON
type PolicyDb struct {
	ID uint64 `sql:"AUTO_INCREMENT"`
	// Policy document as JSON
	Policy string
	// DeletedAt is for using soft delete functionality
	// from http://jinzhu.me/gorm/curd.html#delete
	DeletedAt *time.Time
}

// isValidProto checks if the Protocol specified in Rule is valid.
// The following protocols are recognized:
// - any -- wildcard
// - tcp
// - udp
// - icmp
func isValidProto(proto string) bool {
	switch proto {
	case "icmp", "tcp", "udp":
		return true
	// Wildcard
	case Wildcard:
		return true
	}
	return false
}

// validate validates Rules.
func validateRules(rules Rules) []string {
	errMsg := make([]string, 0)
	if rules == nil || len(rules) == 0 {
		errMsg = append(errMsg, "No rules specified.")
		return errMsg
	}
	for i, r := range rules {
		// ruleNo is used for error messages.
		ruleNo := i + 1
		r.Protocol = strings.TrimSpace(strings.ToLower(r.Protocol))
		if r.Protocol == "" {
			errMsg = append(errMsg, fmt.Sprintf("Rule #%d: No protocol specified.", ruleNo))
		} else if !isValidProto(r.Protocol) {
			errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid protocol: %s.", ruleNo, r.Protocol))
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
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: The following port ranges are invalid: %s.", ruleNo, strings.Join(badRanges, ", ")))
			}
			badPorts := make([]string, 0)
			for _, port := range r.Ports {
				if port < 0 || port > MaxPortNumber {
					badPorts = append(badPorts, fmt.Sprintf("%d", port))
				}
			}
			if len(badPorts) > 0 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: The following ports are invalid: %s.", ruleNo, strings.Join(badPorts, ", ")))
			}
		}
		if r.Protocol != "icmp" {
			if r.IcmpCode > 0 || r.IcmpType > 0 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: ICMP protocol is not specified but ICMP Code and/or ICMP Type are also specified.", ruleNo))
			}
		} else {
			if len(r.Ports) > 0 || len(r.PortRanges) > 0 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: ICMP protocol is specified but ports are also specified.", ruleNo))
			}
			if r.IcmpType < 0 || r.IcmpType > MaxIcmpType {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP type: %d.", ruleNo, r.IcmpType))
			}
			switch r.IcmpType {
			case 3: // Destination unreachable
				if r.IcmpCode < 0 || r.IcmpCode > 15 {
					errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
				}
			case 4: // Source quench
				if r.IcmpCode != 0 {
					errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
				}
			case 5: // Redirect
				if r.IcmpCode < 0 || r.IcmpCode > 3 {
					errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
				}
			case 11: // Time exceeded
				if r.IcmpCode < 0 || r.IcmpCode > 1 {
					errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
				}
			default:
				if r.IcmpCode != 0 {
					errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
				}

			}

		}
	}
	if len(errMsg) == 0 {
		return nil
	}
	return errMsg
}

// Validate validates the policy and returns an Unprocessable Entity (422) HttpError if the policy
// is invalid. The following would lead to errors if they are not specified elsewhere:
// 1. Rules must be specified.
// TODO As a reference I'm using
// https://docs.google.com/spreadsheets/d/1vN-EnZqJnIp8krY1cRf6VzRPkO9_KNYLW0QOfw2k1Mo/edit
// which we'll remove from this comment once finalized.
func (p *Policy) Validate() error {
	var errMsg []string
	// 1. Validate that direction is one of the allowed two values.
	p.Direction = strings.TrimSpace(strings.ToLower(p.Direction))
	if p.Direction != PolicyDirectionEgress && p.Direction != PolicyDirectionIngress {
		s := fmt.Sprintf("Unknown direction '%s', allowed '%s' or '%s'.", p.Direction, PolicyDirectionEgress, PolicyDirectionIngress)
		errMsg = append(errMsg, s)
	}
	// 2. Validate rules
	rulesMsg := validateRules(p.Rules)
	if rulesMsg != nil {
		errMsg = append(errMsg, rulesMsg...)
	}

	// 3. Validate AppliedTo

	for i, endpoint := range p.AppliedTo {
		epNo := i + 1
		if endpoint.TenantExternalID == "" && endpoint.TenantID == 0 && endpoint.TenantNetworkID == 0 {
			errMsg = append(errMsg, fmt.Sprintf("applied_to entry #%d: at least one of tenant_id or tenant_external_id or tenant_network_id must be specified.", epNo))
		}
	}
	for i, endpoint := range p.Peers {
		epNo := i + 1
		if endpoint.Any != "" && endpoint.Any != Wildcard {
			errMsg = append(errMsg, fmt.Sprintf("peers entry #%d: Invalid value for Any: '%s', only '' and %s allowed.", epNo, endpoint.Any, Wildcard))
		}
		if endpoint.SegmentID != 0 || endpoint.SegmentExternalID != "" {
			if endpoint.TenantExternalID == "" && endpoint.TenantID == 0 && endpoint.TenantNetworkID == 0 {
				errMsg = append(errMsg, fmt.Sprintf("peers entry #%d: since segment_external_id is specified, at least one of tenant_id or tenant_external_id or tenant_network_id must be specified.", epNo))

			}
		}
	}
	if len(errMsg) == 0 {
		return nil
	} else {
		return NewUnprocessableEntityError(errMsg)
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
	Cidr        string `json:"cidr,omitempty"`
	PrefixBits  uint   `json:"prefix_bits"`
	PortBits    uint   `json:"port_bits"`
	TenantBits  uint   `json:"tenant_bits"`
	SegmentBits uint   `json:"segment_bits"`
	// We don't need to store this, but calculate and pass around
	EndpointBits      uint   `json:"endpoint_bits"`
	EndpointSpaceBits uint   `json:"endpoint_space_bits"`
	Name              string `json:"name"`
}
