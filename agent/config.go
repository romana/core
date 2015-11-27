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

package agent

import (
	"github.com/romana/core/common"
	"github.com/romana/core/topology"

	"log"
	"net"
)

// NetworkConfig holds the agent's current configuration.
// This consists of data parsed from the config file as well as
// runtime or discovered configuration, such as the network
// config of the current host.
type NetworkConfig struct {
	// Current host network configuration
	currentHostIP        net.IP
	currentHostGW        net.IP
	currentHostGWNet     net.IPNet
	currentHostGWNetSize int
	// index of the current host in POC config file
	currentHostIndex int
	hosts            []common.HostMessage
	dc               topology.Datacenter
}

// EndpointNetmaskSize returns integer value (aka size) of endpoint netmask.
func (c *NetworkConfig) EndpointNetmaskSize() uint64 {
	// TODO make this depend on the IP version
	return 32 - uint64(c.dc.EndpointSpaceBits)
}

// PNetCIDR returns pseudo net cidr in net.IPNet format.
func (c *NetworkConfig) PNetCIDR() (cidr *net.IPNet, err error) {
	_, cidr, err = net.ParseCIDR(c.dc.Cidr)
	return
}

// TenantBits returns tenant bits value from POC config.
func (c *NetworkConfig) TenantBits() uint {
	return c.dc.TenantBits
}

// SegmentBits returns segment bits value from POC config.
func (c *NetworkConfig) SegmentBits() uint {
	return c.dc.SegmentBits
}

// EndpointBits returns endpoint bits value from POC config.
func (c *NetworkConfig) EndpointBits() uint {
	return c.dc.EndpointBits
}

// identifyCurrentHost discovers network configuration
// of the host we are running on.
// We need to know public IP and pani gateway IP of the current host.
// This is done by matching current host IP addresses against what topology
// service thinks the host address is.
// If no match is found we assume we are running on host which is not
// part of the Romana setup and spit error out.
func (a Agent) identifyCurrentHost() error {
	topologyURL, err := common.GetServiceUrl(a.config.Common.Api.RootServiceUrl, "topology")
	if err != nil {
		return agentError(err)
	}

	client, err := common.NewRestClient(topologyURL)
	if err != nil {
		return agentError(err)
	}
	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return agentError(err)
	}
	dcURL := index.Links.FindByRel("datacenter")
	dc := common.Datacenter{}
	err = client.Get(dcURL, &dc)
	if err != nil {
		return agentError(err)
	}

	hostURL := index.Links.FindByRel("host-list")
	hosts := []common.HostMessage{}
	err = client.Get(hostURL, &hosts)
	if err != nil {
		return agentError(err)
	}

	// Walking through all interfaces on a host and looking for a
	// matching interface address in configuration.
	addrs, _ := net.InterfaceAddrs()
	for i := range addrs {
		romanaIP, _, err := net.ParseCIDR(addrs[i].String())
		if err != nil {
			log.Printf("Failed to parse %s", addrs[i].String())
			return err
		}
		// Walking through host addresses in our config and looking
		// for a match to current interface address
		for j := range hosts {
			_, romanaNet, err := net.ParseCIDR(hosts[j].RomanaIp)
			if err != nil {
				log.Printf("Failed to parse %s", hosts[j].RomanaIp)
				return err
			}
			log.Printf("Init:IdentifyCurrentHost %s belongs to %s %s",
				romanaNet,
				romanaIP,
				romanaNet.Contains(romanaIP))

			// Found it
			if romanaNet.Contains(romanaIP) {
				a.networkConfig.currentHostIP = net.ParseIP(hosts[j].Ip)
				a.networkConfig.currentHostGW = romanaIP
				a.networkConfig.currentHostGWNet = *romanaNet
				a.networkConfig.currentHostGWNetSize, _ = romanaNet.Mask.Size()
				a.networkConfig.currentHostIndex = j
				a.networkConfig.hosts = hosts
				return nil
			}
		}
	}
	return wrongHostError()
}
