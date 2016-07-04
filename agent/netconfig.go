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

package agent

import (
	"encoding/json"
	"net"
)

const (
	// Name of the option (see Options field in
	// NetIf below) that specifies Kubernetes
	// namespace isolation value (on/off).
	namespaceIsolationOption = "namespace_isolation"
)

// NetworkRequest specifies messages sent to the
// agent containing information on how to configure network
// on its host.
type NetworkRequest struct {
	NetIf NetIf `json:"net_if,omitempty"`
	// TODO we should not need this tag
	Options map[string]string `json:"options,omitempty"`
}

// NetIf is a structure that represents
// network interface and its IP configuration
// together with basic methods operating on this structure.
type NetIf struct {
	Name string `form:"interface_name" json:"interface_name"`
	Mac  string `form:"mac_address" json:"interface_name,omitempty"`
	IP   net.IP `form:"ip_address" json:"ip_address,omitempty"`
}

// GetName implements firewall.FirewallEndpoint
func (i NetIf) GetName() string {
	return i.Name
}

// GetMac implements firewall.FirewallEndpoint
func (i NetIf) GetMac() string {
	return i.Mac
}

// GetIP implements firewall.FirewallEndpoint
func (i NetIf) GetIP() net.IP {
	return i.IP
}

// SetIP parses and sets the IP address of the interface.
func (netif *NetIf) SetIP(ip string) error {
	netif.IP = net.ParseIP(ip)
	if netif.IP == nil {
		return failedToParseNetif()
	}
	return nil
}

// UnmarshalJSON results in having NetIf implement Unmarshaler
// interface from encoding/json. This is needed because we use
// a type like net.IP here, not a simple type, and so a call to
// net.ParseIP is required to unmarshal this properly.
func (netif *NetIf) UnmarshalJSON(data []byte) error {
	m := make(map[string]string)
	json.Unmarshal(data, &m)

	netif.IP = net.ParseIP(m["ip_address"])
	if netif.IP == nil {
		return failedToParseNetif()
	}

	netif.Name = m["interface_name"]
	netif.Mac = m["mac_address"]
	return nil
}
