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

package agent

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
)

// NetworkConfig holds the agent's current configuration.
// This consists of data parsed from the config file as well as
// runtime or discovered configuration, such as the network
// config of the current host.
// NetworkConfig public methods are used to implement
// firewall.NetConfig interface.
type NetworkConfig struct {
	// Current host network configuration
	sync.Mutex
	romanaGW        net.IP
	romanaGWMask    net.IPMask
	oldRomanaGW     net.IP
	oldRomanaGWMask net.IPMask
	otherHosts      []common.Host
	dc              common.Datacenter
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

// PrefixBits returns tenant bits value from POC config.
func (c *NetworkConfig) PrefixBits() uint {
	return c.dc.PrefixBits
}

// PortBits returns tenant bits value from POC config.
func (c *NetworkConfig) PortBits() uint {
	return c.dc.PortBits
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

// RomanaGWMask returns current romana gateway mask.
func (c *NetworkConfig) RomanaGWMask() net.IPMask {
	return c.romanaGWMask
}

// updateRomanaGWMask updates romana gateway and mask to new
// value and moves the old one to old* variables. The old
// address and mask are used later to identify the address
// we need to delete from the Romana GW interface.
func (c *NetworkConfig) updateRomanaGWMask(ipnet *net.IPNet) {
	c.Lock()
	defer c.Unlock()

	log.Tracef(4, "Current Romana Gateway: %s/%s", c.romanaGW, c.romanaGWMask)
	log.Tracef(4, "New Romana Gateway: %s", ipnet.String())

	c.oldRomanaGW = c.romanaGW
	c.oldRomanaGWMask = c.romanaGWMask
	c.romanaGW = ipnet.IP
	c.romanaGWMask = ipnet.Mask
}

// identifyCurrentHost contacts topology service and get
// details about the node the agent is running on, it then
// populates IP and Mask fields, by comparing hostname with
// one received from topology service.
func (a Agent) identifyCurrentHost() error {
	log.Trace(trace.Private, "In Agent identifyCurrentHost()")

	topologyURL, err := a.client.GetServiceUrl("topology")
	if err != nil {
		return agentError(err)
	}
	index := common.IndexResponse{}
	err = a.client.Get(topologyURL, &index)
	if err != nil {
		return agentError(err)
	}
	dcURL := index.Links.FindByRel("datacenter")
	a.networkConfig.dc = common.Datacenter{}
	err = a.client.Get(dcURL, &a.networkConfig.dc)
	if err != nil {
		return agentError(err)
	}

	hostURL := index.Links.FindByRel("host-list")
	hosts := []common.Host{}
	err = a.client.Get(hostURL, &hosts)
	if err != nil {
		return agentError(err)
	}
	log.Trace(trace.Inside, "Retrieved hosts list, found", len(hosts), "hosts")

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}

	log.Tracef(trace.Inside, "Searching %d interfaces for a matching host configuration: %v", len(addrs), addrs)

	for _, host := range hosts {
		for _, addr := range addrs {
			if strings.Contains(addr.String(), host.Ip) {

				_, ipnet, err := net.ParseCIDR(host.RomanaIp)
				if err != nil {
					return fmt.Errorf("Unable to parse Romana IP Address: %s", host.RomanaIp)
				}

				romanaIP, err := GetFirstIPinCIDR(ipnet)
				if err != nil {
					fmt.Println(err)
				}
				log.Debug("Assigning Romana IP: ", romanaIP)

				a.networkConfig.updateRomanaGWMask(romanaIP)

				log.Trace(trace.Inside, "Found match for host", host, "using address", addr)

				return nil
			}
		}
	}

	return agentErrorString("Unable to identify current host, host not added to romana cluster.")
}

// updateRoutes discovers network configuration
// of the host we are running on.
// We need to know public IP and Romana gateway IP of the current host.
// This is done by matching current host IP addresses against what topology
// service thinks the host address is.
// If no match is found we assume we are running on host which is not
// part of the Romana setup and spit error out.
func (a Agent) updateRoutes() error {
	log.Trace(trace.Private, "In Agent updateRoutes()")

	topologyURL, err := a.client.GetServiceUrl("topology")
	if err != nil {
		return agentError(err)
	}
	index := common.IndexResponse{}
	err = a.client.Get(topologyURL, &index)
	if err != nil {
		return agentError(err)
	}
	dcURL := index.Links.FindByRel("datacenter")
	a.networkConfig.dc = common.Datacenter{}
	err = a.client.Get(dcURL, &a.networkConfig.dc)
	if err != nil {
		return agentError(err)
	}

	hostURL := index.Links.FindByRel("host-list")
	hosts := []common.Host{}
	err = a.client.Get(hostURL, &hosts)
	if err != nil {
		return agentError(err)
	}
	log.Trace(trace.Inside, "Retrieved hosts list, found", len(hosts), "hosts")

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}

	log.Tracef(trace.Inside, "Searching %d interfaces for a matching host configuration: %v", len(addrs), addrs)

	// Find an interface that matches a Romana CIDR
	// and store that interface's IP address.
	// It will be used when configuring iptables and routes to tap interfaces.
	for i, host := range hosts {
		_, romanaCIDR, err := net.ParseCIDR(host.RomanaIp)
		if err != nil {
			log.Tracef(trace.Inside, "Unable to parse '%s' (%s). Skipping.", host.RomanaIp, err)
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

				// Check if romanaGW address was changed recently, if it was
				// then remove the old one and set the new one we received.
				//
				// romana-gw can change due to multiple reasons:
				// * when node is cordoned/un-cordoned thus no pods except
				//   daemon set are there.
				// * when node is rebooted and it takes it long enough that the
				//   current cidr was re-allocated to other node.
				//
				romanaGWMaskSize, _ := a.networkConfig.romanaGWMask.Size()
				ipnetMaskSize, _ := ipnet.Mask.Size()
				if !a.networkConfig.romanaGW.Equal(ipnet.IP) ||
					romanaGWMaskSize != ipnetMaskSize {

					// For now we don't need updating romanaGW address
					// and mask, so disable it, but do log a message
					// about it.
					if true {
						log.Error("Agent: romana gateway IP Address/Mask changed on the node.")
					} else {
						a.networkConfig.updateRomanaGWMask(ipnet)

						// Update Romana Gateway with new config.
						if err := a.createRomanaGW(); err != nil {
							log.Error("Agent: Failed to update romana gateway IP Address on the node:", err)
							return err
						}
					}
				}

				log.Trace(trace.Private, "Acquiring mutex identifyCurrentHost")
				a.Helper.ensureInterHostRoutesMutex.Lock()

				// Retain the other hosts that were listed.
				// This will be used for creating inter-host routes.
				a.networkConfig.otherHosts = append(a.networkConfig.otherHosts, hosts[0:i]...)
				a.networkConfig.otherHosts = append(a.networkConfig.otherHosts, hosts[i+1:]...)
				log.Trace(trace.Inside, "Found match for CIDR", romanaCIDR, "using address", ipnet.IP)

				log.Trace(trace.Private, "Releasing mutex identifyCurrentHost")
				a.Helper.ensureInterHostRoutesMutex.Unlock()

				return nil
			}
		}
	}
	return agentErrorString("Unable to find interface matching any Romana CIDR")
}

func GetFirstIPinCIDR(ipnet *net.IPNet) (*net.IPNet, error) {
	if ipnet == nil {
		return nil, fmt.Errorf("Agent Error, no input provided to GetFirstIPinCIDR")
	}
	if ipnet.IP.String() == "<nil>" || ipnet.Mask.String() == "<nil>" {
		return nil, fmt.Errorf("Agent Error, invalid IP/Mask provided to GetFirstIPinCIDR")
	}

	ip := ipnet.IP.Mask(ipnet.Mask)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}

	if !ipnet.Contains(ip) {
		return nil, fmt.Errorf("Error, no more IP address left in the network provided: %s", ipnet.String())
	}

	return &net.IPNet{IP: ip, Mask: ipnet.Mask}, nil
}
