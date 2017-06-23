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
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"github.com/romana/core/common"
	"net"
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
	Name string `form:"interface_name" sql:"unique"`
	Mac  string `form:"mac_address" gorm:"primary_key"`
	IP   IP     `form:"ip_address" sql:"TYPE:varchar"`
}

// MarshalJSON properly marshals NetIf structure.
func (n NetIf) MarshalJSON() ([]byte, error) {
	m := make(map[string]string)
	m["interface_name"] = n.Name
	m["mac_address"] = n.Mac
	m["ip_address"] = n.IP.String()
	return json.Marshal(m)
}

// IP structure is basically net.IP, but we redefine it so we
// can implement Valuer and Scanner interfaces on it for storage.
type IP struct {
	net.IP
}

// Value implements driver.Valuer interface on IP
func (i IP) Value() (driver.Value, error) {
	return driver.Value(i.String()), nil
}

// NewNetIf is a simple constructor for NetIf
func NewNetIf(ifname string, mac string, ip string) NetIf {
	return NetIf{Name: ifname, Mac: mac, IP: IP{net.ParseIP(ip)}}
}

// Scan implements driver.Scanner interface on IP
func (i *IP) Scan(src interface{}) error {
	switch src := src.(type) {
	case string:
		ip := net.ParseIP(src)
		if ip == nil {
			return common.NewError("Cannot parse IP %s", src)
		}
		i.IP = ip
		return nil
	case []uint8:
		i.IP = net.ParseIP(string(src))
		return nil
	default:
		return common.NewError("Incompatible type for IP")
	}
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
	return i.IP.IP
}

// SetIP parses and sets the IP address of the interface.
func (netif *NetIf) SetIP(ip string) error {
	netif.IP.IP = net.ParseIP(ip)
	if netif.IP.IP == nil && ip != "" {
		return failedToParseNetif(fmt.Sprintf("Bad IP: %s", ip))
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
	ip := m["ip_address"]
	netif.IP.IP = net.ParseIP(ip)
	if netif.IP.IP == nil && ip != "" {
		return failedToParseNetif(fmt.Sprintf("Bad IP: %s", ip))
	}

	netif.Name = m["interface_name"]
	netif.Mac = m["mac_address"]
	return nil
}
