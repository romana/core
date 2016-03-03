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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package agent

import (
	//	"fmt"
	//	"log"
	"encoding/json"
	"net"
)

// NetIf is a structure that represents
// network interface and its ip configuration
// together with basic methods operating on this structure.
type NetIf struct {
	Name string `form:"interface_name" json:"interface_name"`
	Mac  string `form:"mac_address" json:"interface_name"`
	IP  net.IP `form:"ip_address" json:"ip_address"`
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
