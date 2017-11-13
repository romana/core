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
	"net"
)

// TODO should this really be kept alongside BlocksResponse?
type Tenant struct {
	ID       string    `json:"id"`
	Segments []Segment `json:"segments"`
}

type Segment struct {
	ID     string  `json:"id"`
	Blocks []IPNet `json:"blocks"`
}

type IPAMAddressResponse struct {
	Name string `json:"id"`
	IP   net.IP `json:"ip"`
}

type IPAMAddressRequest struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Tenant  string `json:"tenant"`
	Segment string `json:"segment"`
}

type IPAMNetworkResponse struct {
	Revision int    `json:"revision"`
	Name     string `json:"id"`
	CIDR     IPNet  `json:"cidr"`
}

type IPAMBlocksResponse struct {
	Revision int                 `json:"revision"`
	Blocks   []IPAMBlockResponse `json:"blocks"`
}

type IPAMBlockResponse struct {
	Revision         int    `json:"revision"`
	CIDR             IPNet  `json:"cidr"`
	Tenant           string `json:"tenant"`
	Segment          string `json:"segment"`
	Host             string `json:"host"`
	AllocatedIPCount int    `json:"allocated_ip_count"`
}

type TopologyUpdateRequest struct {
	Networks   []NetworkDefinition  `json:"networks"`
	Topologies []TopologyDefinition `json:"topologies"`
}

type NetworkDefinition struct {
	Name      string `json:"name"`
	CIDR      string `json:"cidr"`
	BlockMask uint   `json:"block_mask"`
	// List of allowed tenants.
	Tenants []string `json:"tenants,omitempty"`
}

type TopologyDefinition struct {
	Networks []string      `json:"networks"`
	Map      []GroupOrHost `json:"map"`
}

type GroupOrHost struct {
	// Assignment is a map of key-value pairs that specify what attributes (key=value)
	// of a new host to use to assign it into a group.
	Assignment map[string]string `json:"assignment,omitempty"`
	Routing    string            `json:"routing,omitempty"`
	Groups     []GroupOrHost     `json:"groups"`

	// If the below are specified, this GroupSpec really represents a host,
	// therefore the above elements MUST NOT be specified.
	Name string `json:"name"`
	IP   net.IP `json:"ip,omitempty"`

	// A dummy group is one used for padding to power of 2; it is not to
	// be assigned hosts to
	Dummy bool `json:"dummy"`
}

type Host struct {
	IP        net.IP `json:"ip"`
	Name      string `json:"name"`
	AgentPort uint   `json:"agent_port"`
	// TODO this is a placeholder for now so that agent builds
	RomanaIp string            `json:"romana_ip"`
	Tags     map[string]string `json:"tags"`
	K8SInfo  map[string]string `json:"k8s_info"`
}

func (h Host) String() string {
	val := fmt.Sprintf("%s (IP: %s)", h.Name, h.IP)
	if h.Tags != nil && len(h.Tags) > 0 {
		val += fmt.Sprintf(" Tags: %s", h.Tags)
	}
	if h.K8SInfo != nil && len(h.K8SInfo) > 0 {
		val += fmt.Sprintf(" Kubernetes info: %s", h.K8SInfo)
	}
	return val
}

type HostList struct {
	Hosts    []Host `json:"hosts"`
	Revision int    `json:"revision"`
}

type IPNet struct {
	net.IPNet
}

func (ip IPNet) MarshalText() ([]byte, error) {
	return []byte(ip.IPNet.String()), nil
}

func (ip *IPNet) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		ip = nil
		return nil
	}

	cidrLit := string(text)
	_, ipnet, err := net.ParseCIDR(cidrLit)
	if err != nil {
		return &net.ParseError{Type: "Cidr", Text: cidrLit}
	}

	*ip = IPNet{*ipnet}
	return nil
}
