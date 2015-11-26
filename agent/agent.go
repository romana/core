// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// This is a Romana service which provides networking functions on the host.
package agent

import (
	"fmt"
	"github.com/romana/core/common"
	"log"
)

// Agent provides access to configuration and helper functions, shared across
// all the threads.
// Types Config, Leasefile and Firewall are designed to be loosely coupled
// so they could later be separated into packages and used independently.
type Agent struct {
	// Discovered run-time configuration.
	networkConfig *NetworkConfig

	config common.ServiceConfig
	// Leasefile is a type that manages DHCP leases in the file
	leaseFile *LeaseFile

	// Helper here is a type that organizes swappable interfaces for 3rd
	// party libraries (e.g. os.exec), and some functions that are using
	// those interfaces directly. Main purpose is to support unit testing.
	// Choice of having Helper as a field of an Agent is made to
	// support multiple instances of an Agent running at same time.
	// We like this approach, since it gives us flexibility as the agent evolves in the future.
	// Should this flexibility not be required, a suitable alternative is to re-implement the
	// Agent structure as a set of global variables.
	Helper *Helper

	waitForIfaceTry int
}

// SetConfig implements SetConfig function of the Service interface.
func (agent *Agent) SetConfig(config common.ServiceConfig) error {
	log.Println(config)
	agent.config = config
	leaseFileName := config.ServiceSpecific["lease_file"].(string)
	lf := NewLeaseFile(leaseFileName, agent)
	agent.leaseFile = &lf

	agent.waitForIfaceTry = int(config.ServiceSpecific["wait_for_iface_try"].(float64))
	agent.networkConfig = &NetworkConfig{}
	log.Printf("Agent.SetConfig() finished.")
	return nil
}

// Routes implements Routes function of Service interface.
func (agent *Agent) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			"POST",
			"/",
			agent.index,
			func() interface{} {
				return &NetIf{}
			},
		},
	}
	return routes
}

// Run runs the agent service.
func Run(rootServiceUrl string) (chan common.ServiceMessage, error) {
	agent := &Agent{}
	helper := NewAgentHelper(agent)
	agent.Helper = &helper
	log.Printf("Agent: Getting configuration from %s", rootServiceUrl)
	config, err := common.GetServiceConfig(rootServiceUrl, "agent")
	if err != nil {
		return nil, err
	}
	ch, err := common.InitializeService(agent, *config)
	return ch, err
}

// interfaceHandler handles HTTP requests for endpoints provisioning.
// Currently tested with pani ML2 driver.
func (a *Agent) index(input interface{}, ctx common.RestContext) (interface{}, error) {
	// Parse out NetIf form the request
	netif := input.(NetIf)
	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.interfaceHandle(netif)

	// TODO I wonder if this should actually return something like a
	// link to a status of this request which will later get updated
	// with success or failure -- Greg.
	return "OK", nil
}

// interfaceHandle does a number of opertaions on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Ensures interhost routes are in place
// 3. Checks if DHCP is running
// 4. Creates ip route pointing new interface
// 5. Provisions static DHCP lease for new interface
// 6. Provisions firewall rules
func (a *Agent) interfaceHandle(netif NetIf) error {
	log.Print("Agent: processing request to provision new interface")
	if !a.Helper.waitForIface(netif.Name) {
		// TODO should we resubmit failed interface in queue for later
		// retry ? ... considering oenstack will give up as well after
		// timeout
		return agentErrorString(fmt.Sprintf("Requested interface not available in time - %s", netif.Name))
	}

	// Ensure we have all the routes to our neighbours
	log.Print("Agent: ensuring interhost routes exist")
	if err := a.Helper.ensureInterHostRoutes(); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	// dhcpPid is only needed here for fail fast check
	// will try to poll the pid again in provisionLease
	log.Print("Agent: checking if DHCP is running")
	_, err := a.Helper.DhcpPid()
	if err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	log.Print("Agent: creating endpoint routes")
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	log.Print("Agent: provisioning DHCP")
	if err := a.leaseFile.provisionLease(&netif); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	log.Print("Agent: provisioning firewall")
	if err := provisionFirewallRules(netif, a); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}

	log.Print("All good", netif)
	return nil
}

// Initialize implements the Initialize method of common.Service
// interface.
func (agent *Agent) Initialize() error {
	log.Printf("Entering Agent.Initialize()")
	return agent.identifyCurrentHost()
}

/* development code
func DryRun() {
	tif := NetIf{"eth0", "B", "10.0.0.1"}
	firewall, _ := NewFirewall(tif)
	err := firewall.ParseNetIf(tif)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(firewall.u32Filter)
	// for chain := range firewall.chains {
	// 	fmt.Println(firewall.chains[chain])
	// }
	firewall.CreateChains([]int{1, 2, 3})
	a.Helper.ensureInterHostRoutes()
	if _, err := a.Helper.DhcpPid(); err != nil {
		fmt.Println(err)
	}
}
*/
