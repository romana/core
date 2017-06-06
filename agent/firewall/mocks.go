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
//
// Fake structures used in testing.

package firewall

import (
	"github.com/romana/core/common"
	"net"
	"sync"
)

// mockNetworkConfig implements NetConfig
type mockNetworkConfig struct{}

// EndpointNetmaskSize returns integer value (aka size) of endpoint netmask.
func (c mockNetworkConfig) EndpointNetmaskSize() uint64 {
	// dc.EndpointSpaceBits = 0
	return 32
}

// PNetCIDR returns pseudo net cidr in net.IPNet format.
func (c mockNetworkConfig) PNetCIDR() (cidr *net.IPNet, err error) {
	// dc.Cidr = "10.0.0.0/8"
	_, cidr, err = net.ParseCIDR("10.0.0.0/8")
	return
}

// PrefixBits returns tenant bits value from POC config.
func (c mockNetworkConfig) PrefixBits() uint {
	return uint(8)
}

// PortBits returns tenant bits value from POC config.
func (c mockNetworkConfig) PortBits() uint {
	return uint(8)
}

// TenantBits returns tenant bits value from POC config.
func (c mockNetworkConfig) TenantBits() uint {
	// dc.TenantBits = 4
	return uint(4)
}

// SegmentBits returns segment bits value from POC config.
func (c mockNetworkConfig) SegmentBits() uint {
	// dc.SegmentBits = 4
	return uint(4)
}

// EndpointBits returns endpoint bits value from POC config.
func (c mockNetworkConfig) EndpointBits() uint {
	// dc.EndpointBits = 8
	return uint(8)
}

// RomanaGW returns current romana gateway.
func (c mockNetworkConfig) RomanaGW() net.IP {
	// {Ip: "172.17.0.1"}
	return net.ParseIP("172.17.0.1")
}

// mockNetworkConfig implements FirewallEndpoint
type mockFirewallEndpoint struct {
	Name string
	Mac  string
	IP   net.IP
}

func (c mockFirewallEndpoint) GetName() string {
	return c.Name
}

func (c mockFirewallEndpoint) GetMac() string {
	return c.Mac
}

func (c mockFirewallEndpoint) GetIP() net.IP {
	return c.IP
}

func makeMockStore() firewallStore {
	// Initialize database.
	storeConfig := common.ServiceConfig{ServiceSpecific: map[string]interface{}{
		"type":     "sqlite3",
		"database": "/tmp/agent.db"},
	}
	mockStore := firewallStore{}
	mockStore.ServiceStore = &mockStore
	cfg, _ := common.MakeStoreConfig(storeConfig.ServiceSpecific)
	mockStore.SetConfig(cfg)
	mockStore.CreateSchema(true) // overwrite
	mockStore.mu = new(sync.RWMutex)

	return mockStore
}
