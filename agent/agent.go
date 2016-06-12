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
	"github.com/golang/glog"
	"github.com/romana/core/common"
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

	// Agent store to keep records about managed resources.
	store agentStore
}

// SetConfig implements SetConfig function of the Service interface.
func (a *Agent) SetConfig(config common.ServiceConfig) error {
	glog.Infoln(config)
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

	glog.Infof("Agent.SetConfig() finished.")
	return nil
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
			Method:  "DELETE",
			Pattern: "/pod",
			Handler: a.k8sPodDownHandler,
			MakeMessage: func() interface{} {
				return &NetworkRequest{}
			},
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
		common.Route{
			Method:  "GET",
			Pattern: "/status",
			Handler: a.statusHandler,
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
	glog.Infof("Agent: Getting configuration from %s", rootServiceURL)

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

// Initialize implements the Initialize method of common.Service
// interface.
func (a *Agent) Initialize() error {
	glog.Infof("Entering Agent.Initialize()")
	err := a.store.Connect()
	if err != nil {
		glog.Error("Agent.Initialize() : Failed to connect to database.")
		return err
	}

	glog.Infof("Attempting to identify current host.")
	if err := a.identifyCurrentHost(); err != nil {
		glog.Error("Agent: ", agentError(err))
		return agentError(err)
	}

	// Ensure we have all the routes to our neighbours
	glog.Info("Agent: ensuring interhost routes exist")
	if err := a.Helper.ensureInterHostRoutes(); err != nil {
		glog.Error("Agent: ", agentError(err))
		return agentError(err)
	}
	return nil
}

// CreateSchema creates database schema.
func CreateSchema(rootServiceUrl string, overwrite bool) error {
	glog.Infoln("In CreateSchema(", rootServiceUrl, ",", overwrite, ")")
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

func (a *Agent) createSchema(overwrite bool) error {
	return a.store.CreateSchema(overwrite)
}

// addNetworkInterface creates new NetworkInterface record in database.
func (a *Agent) addNetworkInterface(netif NetIf) error {
	iface := &NetworkInterface{Name: netif.Name, Status: "active"}
	return a.store.addNetworkInterface(iface)
}
