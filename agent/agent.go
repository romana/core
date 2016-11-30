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
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
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
	TestMode bool

	// Agent store to keep records about managed resources.
	store agentStore

	client *common.RestClient
}

// SetConfig implements SetConfig function of the Service interface.
func (a *Agent) SetConfig(config common.ServiceConfig) error {
	log.Trace(trace.Public, config)
	a.config = config
	leaseFileName := config.ServiceSpecific["lease_file"].(string)
	lf := NewLeaseFile(leaseFileName, a)
	a.leaseFile = &lf

	a.waitForIfaceTry = int(config.ServiceSpecific["wait_for_iface_try"].(float64))
	a.networkConfig = &NetworkConfig{}

	a.store = *NewStore(config)

	log.Trace(trace.Inside, "Agent.SetConfig() finished.")
	return nil
}

// Routes implements Routes function of Service interface.
func (a *Agent) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:  "GET",
			Pattern: "/",
			Handler: a.statusHandler,
		},
		common.Route{
			Method:  "POST",
			Pattern: "/vm",
			Handler: a.vmUpHandler,
			MakeMessage: func() interface{} {
				return &NetIf{}
			},
			UseRequestToken: false,
		},
		common.Route{
			Method:  "DELETE",
			Pattern: "/vm",
			Handler: a.vmDownHandler,
			MakeMessage: func() interface{} {
				return &NetIf{}
			},
			UseRequestToken: false,
		},
		common.Route{
			Method:  "POST",
			Pattern: "/pod",
			Handler: a.podUpHandler,
			MakeMessage: func() interface{} {
				return &NetworkRequest{}
			},
			// TODO this is for the future so we ensure idempotence.
			UseRequestToken: true,
		},
		common.Route{
			Method:  "DELETE",
			Pattern: "/pod",
			Handler: a.podDownHandler,
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
	}
	return routes
}

// Name implements method of Service interface.
func (a *Agent) Name() string {
	return "agent"
}

// Initialize implements the Initialize method of common.Service
// interface.
func (a *Agent) Initialize(client *common.RestClient) error {
	log.Trace(trace.Public, "Entering Agent.Initialize()")
	err := a.store.Connect()
	if err != nil {
		log.Error("Agent.Initialize() : Failed to connect to database.")
		return err
	}

	log.Info("Agent: Attempting to identify current host.")
	if err := a.identifyCurrentHost(); err != nil {
		log.Error("Agent: ", agentError(err))
		return agentError(err)
	}

	a.client = client
	// Ensure we have all the routes to our neighbours
	log.Info("Agent: ensuring interhost routes exist")
	if err := a.Helper.ensureInterHostRoutes(); err != nil {
		log.Error("Agent: ", agentError(err))
		return agentError(err)
	}
	return nil
}

// CreateSchema creates database schema.
func (a *Agent) createSchema(overwrite bool) error {
	return a.store.CreateSchema(overwrite)
}
