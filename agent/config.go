// Copyright (c) 2016 Pani Networks
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

package agent

import (
	"github.com/romana/core/common"
	//	"github.com/romana/core/topology"

	"github.com/golang/glog"
	"net"
)

// NetworkConfig holds the agent's current configuration.
// This consists of data parsed from the config file as well as
// runtime or discovered configuration, such as the network
// config of the current host.
type NetworkConfig struct {
	// Current host network configuration
	romanaGW   net.IP
	otherHosts []common.HostMessage
	dc         common.Datacenter
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

// RomanaGW returns current romana gateway.
func (c *NetworkConfig) RomanaGW() net.IP {
	return c.romanaGW
}

// identifyCurrentHost discovers network configuration
// of the host we are running on.
// We need to know public IP and Romana gateway IP of the current host.
// This is done by matching current host IP addresses against what topology
// service thinks the host address is.
// If no match is found we assume we are running on host which is not
// part of the Romana setup and spit error out.
func (a Agent) identifyCurrentHost() error {
	client, err := common.NewRestClient(common.GetRestClientConfig(a.config))

	if err != nil {
		return agentError(err)
	}
	topologyURL, err := client.GetServiceUrl("topology")
	if err != nil {
		return agentError(err)
	}
	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return agentError(err)
	}
	dcURL := index.Links.FindByRel("datacenter")
	a.networkConfig.dc = common.Datacenter{}
	err = client.Get(dcURL, &a.networkConfig.dc)
	if err != nil {
		return agentError(err)
	}

	hostURL := index.Links.FindByRel("host-list")
	hosts := []common.HostMessage{}
	err = client.Get(hostURL, &hosts)
	if err != nil {
		return agentError(err)
	}
	glog.Infoln("Retrieved hosts list, found", len(hosts), "hosts")

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}

	glog.Infof("Searching %d interfaces for a matching host configuration: %v", len(addrs), addrs)

	// Find an interface that matches a Romana CIDR
	// and store that interface's IP address.
	// It will be used when configuring iptables and routes to tap interfaces.
	for i, host := range hosts {
		_, romanaCIDR, err := net.ParseCIDR(host.RomanaIp)
		if err != nil {
			glog.Warningf("Unable to parse '%s' (%s). Skipping.", host.RomanaIp, err)
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if romanaCIDR.Contains(ipnet.IP) {
				// Check that it's the same subnet size
				s1, _ := romanaCIDR.Mask.Size()
				s2, _ := ipnet.Mask.Size()
				if s1 != s2 {
					continue
				}
				// OK, we're happy with this result
				a.networkConfig.romanaGW = ipnet.IP
				// Retain the other hosts that were listed.
				// This will be used for creating inter-host routes.
				a.networkConfig.otherHosts = append(a.networkConfig.otherHosts, hosts[0:i]...)
				a.networkConfig.otherHosts = append(a.networkConfig.otherHosts, hosts[i+1:]...)
				glog.Infoln("Found match for CIDR", romanaCIDR, "using address", ipnet.IP)
				return nil
			}
		}
	}
	return agentErrorString("Unable to find interface matching any Romana CIDR")
}
