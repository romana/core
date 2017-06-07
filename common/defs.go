// Copyright (c) 2015-2017 Pani Networks
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

import "database/sql"

type FindFlag string

const (
	// Flags to store.Find operation
	FindFirst      = "findFirst"
	FindLast       = "findLast"
	FindExactlyOne = "findExactlyOne"
	FindAll        = "findAll"
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
	ContextKeyUser         string = "User"
	ReadWriteTimeoutDelta         = 10

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

// LinkResponse structure represents the commonly occurring
// {
//        "href" : "https://<own-addr>",
//        "rel"  : "self"
//  }
// part of the response.
type LinkResponse struct {
	Href string `json:"href,omitempty"`
	Rel  string `json:"rel,omitempty"`
}

// Type definitions
type ServiceMessage string

// Message to register with the root service the actual
// port a service is listening on.
type PortUpdateMessage struct {
	Port uint64 `json:"port"`
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
	ServiceName string `json:"service_name"`
	Links       Links  `json:"links"`
}

// RootIndexResponse represents a response from the / path
// specific for root service only.
type RootIndexResponse struct {
	ServiceName string            `json:"service_name"`
	Links       Links             `json:"links"`
	Services    []ServiceResponse `json:"services"`
}

// Service information
type ServiceResponse struct {
	Name  string `json:"name"`
	Links Links  `json:"links"`
}

// Datacenter represents the configuration of a datacenter.
type Datacenter struct {
	Id        uint64 `json:"id" sql:"AUTO_INCREMENT"`
	IpVersion uint   `json:"ip_version,omitempty"`
	// We don't need to store this, but calculate and pass around
	Prefix      uint64 `json:"prefix,omitempty"`
	Cidr        string `json:"cidr,omitempty"`
	PrefixBits  uint   `json:"prefix_bits"`
	PortBits    uint   `json:"port_bits"`
	TenantBits  uint   `json:"tenant_bits"`
	SegmentBits uint   `json:"segment_bits"`
	// We don't need to store this, but calculate and pass around
	EndpointBits      uint   `json:"endpoint_bits"`
	EndpointSpaceBits uint   `json:"endpoint_space_bits"`
	Name              string `json:"name,omitempty"`
}

func (dc Datacenter) String() string {
	return String(dc)
}

// Tenant represents a tenant, a top-level entity.
type Tenant struct {
	ID uint64 `sql:"AUTO_INCREMENT" json:"id,omitempty"`
	// ExternalID is an ID of this tenant in a system that is integrated
	// with Romana: e.g., OpenStack.
	ExternalID string    `sql:"not null" json:"external_id,omitempty" gorm:"COLUMN:external_id"`
	Name       string    `json:"name,omitempty"`
	Segments   []Segment `json:"segments,omitempty"`
	NetworkID  uint64    `json:"network_id,omitempty"`
}

// Segment is a subdivision of tenant.
type Segment struct {
	ID         uint64 `sql:"AUTO_INCREMENT" json:"id,omitempty"`
	ExternalID string `sql:"not null" json:"external_id,omitempty" gorm:"COLUMN:external_id"`
	TenantID   uint64 `gorm:"COLUMN:tenant_id" json:"tenant_id,omitempty"`
	Name       string `json:"name,omitempty"`
	NetworkID  uint64 `json:"network_id,omitempty"`
}

// IPAMEndpoint represents an endpoint (a VM, a Kubernetes Pod, etc.)
// that is to get an IP address.
type IPAMEndpoint struct {
	Ip           string         `json:"ip,omitempty"`
	TenantID     string         `json:"tenant_id,omitempty"`
	SegmentID    string         `json:"segment_id,omitempty"`
	HostId       string         `json:"host_id,omitempty"`
	Name         string         `json:"name,omitempty"`
	RequestToken sql.NullString `json:"request_token" sql:"unique"`
	// Ordinal number of this Endpoint in the host/tenant combination
	NetworkID uint64 `json:"-"`
	// Calculated effective network ID of this Endpoint --
	// taking into account stride (endpoint space bits)
	// and alignment thereof. This is used in IP calculation.
	EffectiveNetworkID uint64 `json:"-"`
	// Whether it is in use (for purposes of reclaiming)
	InUse bool
	Id    uint64 `sql:"AUTO_INCREMENT" json:"-"`
}

// IPtablesRule represents a single iptables rule managed by the agent.
// TODO Originally defined in pkg/util/firewall, redefined here only to support
// new way of schema creation.
// WARNING. This might get out of sync with original definition. Stas.
type IPtablesRule struct {
	ID    uint64 `sql:"AUTO_INCREMENT"`
	Body  string
	State string
}
