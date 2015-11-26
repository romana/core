// Copyright (c) 2015 Pani Networks
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

// netif.go contains structure for representing Romana endpoint.
package agent

import (
	//	"fmt"
	//	"log"
	"encoding/json"
	"net"
)

const (
	expectedNumberOfFileds = 3
)

// NetIf is a structure that represents
// network interface and it's ip configuration
// together with basic methods operating on this structure.
type NetIf struct {
	Name string
	Mac  string
	Ip   net.IP
}

// UnmarshalJSON results in having NetIf implement Unmarshaler
// interface from encoding/json
func (netif *NetIf) UnmarshalJSON(data []byte) error {
	m := make(map[string]string)
	json.Unmarshal(data, &m)

	netif.Ip = net.ParseIP(m["ip"])
	if netif.Ip == nil {
		return failedToParseNetif()
	}

	netif.Name = m["name"]
	netif.Mac = m["mac"]
	return nil
}
