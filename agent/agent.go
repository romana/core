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

// Package agent is a Romana service which provides networking functions on the host.
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

	// Whether this is running in test mode.
	testMode bool

	store agentStore
}

// SetConfig implements SetConfig function of the Service interface.
func (a *Agent) SetConfig(config common.ServiceConfig) error {
	log.Println(config)
	a.config = config
	leaseFileName := config.ServiceSpecific["lease_file"].(string)
	lf := NewLeaseFile(leaseFileName, a)
	a.leaseFile = &lf

	a.waitForIfaceTry = int(config.ServiceSpecific["wait_for_iface_try"].(float64))
	a.networkConfig = &NetworkConfig{}

	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	a.store = agentStore{}
	a.store.ServiceStore = &a.store
	a.store.SetConfig(storeConfig)

	log.Printf("Agent.SetConfig() finished.")
	return nil
}

func (a *Agent) createSchema(overwrite bool) error {
	return a.store.CreateSchema(overwrite)
}

// Routes implements Routes function of Service interface.
func (a *Agent) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:  "POST",
			Pattern: "/",
			Handler: a.index,
			MakeMessage: func() interface{} {
				return &NetIf{}
			},
			UseRequestToken: false,
		},
		common.Route{
			Method:  "POST",
			Pattern: "/kubernetes-pod-up",
			Handler: a.k8sPodUpHandler,
			MakeMessage: func() interface{} {
				return &NetworkRequest{}
			},
			// TODO this is for the future so we ensure idempotence.
			UseRequestToken: true,
		},
		common.Route{
			Method:  "POST",
			Pattern: "/policies",
			Handler: a.addPolicy,
			MakeMessage: func() interface{} {
				return &common.Policy{}
			},
			UseRequestToken: false,
		},
		common.Route{
			Method:  "DELETE",
			Pattern: "/policies",
			MakeMessage: func() interface{} {
				return &common.Policy{}
			},
			Handler: a.deletePolicy,
		},
		common.Route{
			Method:  "GET",
			Pattern: "/policies",
			Handler: a.listPolicies,
		},
	}
	return routes
}

// Run starts the agent service.
func Run(rootServiceURL string, cred *common.Credential, testMode bool) (*common.RestServiceInfo, error) {
	clientConfig := common.GetDefaultRestClientConfig(rootServiceURL)
	clientConfig.TestMode = testMode
	client, err := common.NewRestClient(clientConfig)
	clientConfig.Credential = cred

	if err != nil {
		return nil, err
	}

	agent := &Agent{testMode: testMode}
	helper := NewAgentHelper(agent)
	agent.Helper = &helper
	log.Printf("Agent: Getting configuration from %s", rootServiceURL)

	config, err := client.GetServiceConfig(agent.Name())
	if err != nil {
		return nil, err
	}
	return common.InitializeService(agent, *config)
}

// Name implements method of Service interface.
func (a *Agent) Name() string {
	return "agent"
}

// addPolicy is a placeholder. TODO
func (a *Agent) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	//	policy := input.(*common.Policy)
	return nil, nil
}

// deletePolicy is a placeholder. TODO
func (a *Agent) deletePolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	//	policyId := ctx.PathVariables["policyID"]
	return nil, nil
}

// listPolicies is a placeholder. TODO.
func (a *Agent) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
	return nil, nil
}

// k8sPodUpHandler handles HTTP requests for endpoints provisioning.
func (a *Agent) k8sPodUpHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("Agent: Entering k8sPodUpHandler()")
	netReq := input.(*NetworkRequest)

	log.Printf("Agent: Got request for network configuration: %v\n", netReq)
	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.k8sPodUpHandle(*netReq)

	// TODO I wonder if this should actually return something like a
	// link to a status of this request which will later get updated
	// with success or failure -- Greg.
	return "OK", nil
}

// index handles HTTP requests for endpoints provisioning.
// Currently tested with Romana ML2 driver.
// TODO index should be reserved for an actual index, while this function
// need to be renamed as interfaceHandler and need to respond on it's own url.
func (a *Agent) index(input interface{}, ctx common.RestContext) (interface{}, error) {
	// Parse out NetIf form the request
	netif := input.(*NetIf)

	log.Printf("Got interface: Name %s, IP %s Mac %s\n", netif.Name, netif.IP, netif.Mac)
	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.interfaceHandle(*netif)

	// TODO I wonder if this should actually return something like a
	// link to a status of this request which will later get updated
	// with success or failure -- Greg.
	return "OK", nil
}

// k8sPodUpHandle does a number of operations on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Creates ip route pointing new interface
// 3. Provisions firewall rules
func (a *Agent) k8sPodUpHandle(netReq NetworkRequest) error {
	log.Println("Agent: Entering k8sPodUpHandle()")

	netif := netReq.NetIf
	if netif.Name == "" {
		return agentErrorString("Agent: Interface name required")
	}
	if !a.Helper.waitForIface(netif.Name) {
		// TODO should we resubmit failed interface in queue for later
		// retry ? ... considering openstack will give up as well after
		// timeout
		msg := fmt.Sprintf("Requested interface not available in time - %s", netif.Name)
		log.Println("Agent: ", msg)
		return agentErrorString(msg)
	}

	log.Print("Agent: creating endpoint routes")
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}
	log.Print("Agent: provisioning firewall")

	if err := provisionK8SFirewallRules(netReq, a); err != nil {
		log.Print(agentError(err))
		return agentError(err)
	}

	a.addNetworkInterface(netif)
	log.Print("Agent: All good", netif)
	return nil
}

// interfaceHandle does a number of operations on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Checks if DHCP is running
// 3. Creates ip route pointing new interface
// 4. Provisions static DHCP lease for new interface
// 5. Provisions firewall rules
func (a *Agent) interfaceHandle(netif NetIf) error {
	log.Print("Agent: processing request to provision new interface")
	if !a.Helper.waitForIface(netif.Name) {
		// TODO should we resubmit failed interface in queue for later
		// retry ? ... considering oenstack will give up as well after
		// timeout
		return agentErrorString(fmt.Sprintf("Requested interface not available in time - %s", netif.Name))
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

	a.addNetworkInterface(netif)
	log.Print("All good", netif)
	return nil
}

func (a *Agent) addNetworkInterface(netif NetIf) error {
	iface := &NetworkInterface{Name: netif.Name, Status: "active"}
	return a.store.addNetworkInterface(iface)
}

// Initialize implements the Initialize method of common.Service
// interface.
func (a *Agent) Initialize() error {
	err := a.store.Connect()
	if err != nil {
		return err
	}

	log.Printf("Entering Agent.Initialize()")
	if err := a.identifyCurrentHost(); err != nil {
		log.Print("Agent: ", agentError(err))
		return agentError(err)
	}

	// Ensure we have all the routes to our neighbours
	log.Print("Agent: ensuring interhost routes exist")
	if err := a.Helper.ensureInterHostRoutes(); err != nil {
		log.Print("Agent: ", agentError(err))
		return agentError(err)
	}
	return nil
}

func CreateSchema(rootServiceUrl string, overwrite bool) error {
	log.Println("In CreateSchema(", rootServiceUrl, ",", overwrite, ")")
	a := &Agent{}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootServiceUrl))
	if err != nil {
		return err
	}

	config, err := client.GetServiceConfig(a.Name())
	if err != nil {
		return err
	}

	err = a.SetConfig(*config)
	if err != nil {
		return err
	}
	return a.store.CreateSchema(overwrite)
}
