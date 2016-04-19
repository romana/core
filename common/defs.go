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
	Cidr      net.IPNet `json:"-"`
	TenantID  uint64    `json:"tenant_id,omitempty"`
	TenantExternalID string  `json:"tenant_external_id,omitempty"`
	SegmentID uint64    `json:"segment_id,omitempty"`
	SegmentExternalID string `json:"segment_external_id,omitempty"`
}

const (
	PolicyDirectionIngress = "ingress"
	PolicyDirectionEgress  = "egress"
)

type PortRange [2]uint

type Rule struct {
	Protocol   string
	Ports      []uint
	PortRanges []PortRange
	IcmpType   uint
	IcmpCode   uint
	Stateful   bool
}

type Rules []Rule

// Metadata attached to entities for various external environments like openstack/kybernetes
type Tag struct {
	Key   string
	Value string
}

type Policy struct {
	Direction   string     `json:"direction,omitempty"`
	Description string     `json:"description,omitempty"`
	Name        string     `json:"name,omitempty"`
	Id          string     `json:"id,omitempty"`
	AppliedTo   []Endpoint `json:"applied_to,omitempty"`
	Peers       []Endpoint `json:"peers,omitempty"`
	Rules       []Rule     `json:"rule,omitempty"`
	Tags        []Tag      `json:"tags,omitempty"`
}

func (p *Policy) Validate() error {
	errMsg := ""
	p.Direction = strings.ToLower(p.Direction)
	if p.Direction != PolicyDirectionEgress && p.Direction != PolicyDirectionIngress {
		errMsg += fmt.Sprintf("Unknown direction '%s', allowed '%s' or '%s'. ", p.Direction, PolicyDirectionEgress, PolicyDirectionIngress)
	}
	for _, r := range p.Rules {
		r.Protocol = strings.ToLower(r.Protocol)
		if r.Protocol == "tcp" {
			r.Stateful = true
		}
		if r.Protocol != "icmp" {
			if len(r.Ports) > 0 || len(r.PortRanges) > 0 {
				errMsg += "ICMP protocol is specified but ports are also specified. "
			}
		}
	}
	if errMsg == "" {
		return nil
	} else {
		return errors.New(errMsg)
	}
}

type RestServiceInfo struct {
	// Address being listened on
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

// Datacenter represents the configuration of a datacenter
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
