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

// Package agent is a Romana service which provides networking functions on the host.
package agent

import (
	"fmt"
	"net"

	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/core/pkg/policy/enforcer"
	"github.com/romana/core/pkg/util/iptsave"
	policyCache "github.com/romana/core/pkg/util/policy/cache"
	tenantCache "github.com/romana/core/pkg/util/tenant/cache"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
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

	policyEnabled bool

	// disables interhost routes managed by the agent.
	interhostRoutesEnabled bool

	// enables publishing routes to external route manager.
	routePublisher string

	// configuration for external publisher
	routePublisherConfig map[string]string

	// channel that is used by route publisher to receive notifications
	routec chan net.IPNet

	// Manages iptables rules to reflect romana policies.
	enforcer enforcer.Interface

	// Stops policy enforcer.
	policyStop chan struct{}

	// default host interface link
	defaultLink netlink.Link
}

// SetConfig implements SetConfig function of the Service interface.
func (a *Agent) SetConfig(config common.ServiceConfig) error {
	var err error
	log.Trace(trace.Public, config)
	a.config = config
	leaseFileName := config.ServiceSpecific["lease_file"].(string)
	lf := NewLeaseFile(leaseFileName, a)
	a.leaseFile = &lf

	var ok bool
	a.policyEnabled, ok = config.ServiceSpecific["policy_enabled"].(bool)
	if !ok {
		a.policyEnabled = true
	}

	a.interhostRoutesEnabled, ok = config.ServiceSpecific["interhost_routes_enabled"].(bool)
	if !ok {
		a.interhostRoutesEnabled = true
	}

	a.routePublisher, ok = config.ServiceSpecific["route_publisher"].(string)
	if !ok {
		a.routePublisher = "none"
	}

	a.routePublisherConfig, err = ParseRoutePublisherConfig(config.ServiceSpecific["route_publisher_config"])
	if err != nil {
		log.Errorf("%s", err)
		a.routePublisherConfig = nil
	}

	a.waitForIfaceTry = int(config.ServiceSpecific["wait_for_iface_try"].(float64))
	a.networkConfig = &NetworkConfig{}
	store, err := NewStore(config)
	if err != nil {
		return err
	}
	a.store = *store
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
			Pattern: "/romanaip",
			Handler: a.romanaIPPostHandler,
			MakeMessage: func() interface{} {
				return &ExternalIP{}
			},
			UseRequestToken: false,
		},
		common.Route{
			Method:  "DELETE",
			Pattern: "/romanaip",
			Handler: a.romanaIPDeleteHandler,
			MakeMessage: func() interface{} {
				return &ExternalIP{}
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

const (
	// defaultCacheTickTime controls how oftend storage cache is updated.
	defaultCacheTickTime = 5

	// defaultPolicyRefreshSeconds controls how often policy agent checks
	// storage caches for updates and applies changes if any.
	defaultPolicyRefreshSeconds = 2

	// defaultRouteRefreshSeconds controls how often agent checks
	// for route update and applies changes if any.
	defaultRouteRefreshSeconds = 120
)

// Initialize implements the Initialize method of common.Service
// interface.
func (a *Agent) Initialize(client *common.RestClient) error {
	var err error

	log.Trace(trace.Public, "Entering Agent.Initialize()")
	a.client = client

	a.defaultLink, err = a.getDefaultLink()
	if err != nil {
		return fmt.Errorf("Failed to get default link: %s\n", err)
	}

	err = a.store.Connect()
	if err != nil {
		log.Error("Agent.Initialize() : Failed to connect to database.")
		return err
	}

	// identifyCurrentHost() needs to be called at-least once before
	// calling createRomanaGW() to populate romanaGW and romanaGWMask.
	log.Info("Agent: Attempting to identify current host.")
	if err := a.identifyCurrentHost(); err != nil {
		log.Error("Agent: Failed to identify current host: ", agentError(err))
		return agentError(err)
	}

	// Create Romana Gateway and bring up the necessary config for it
	// for example: assign IP Address to it, etc.
	if err := a.createRomanaGW(); err != nil {
		log.Error("Agent: Failed to create Romana Gateway on the node:", err)
		return err
	}

	// Enable default kernel settings needed by romana, for example:
	// ip forward, proxy arp, etc
	if err := a.enableRomanaKernelDefaults(); err != nil {
		log.Error("Agent: Failed to enable Romana kernel defaults on the node:", err)
		return err
	}

	// Will try to refresh routes every routeRefreshSeconds.
	var routeRefreshSeconds int
	if a.config.ServiceSpecific["route_refresh_seconds"] != nil {
		routeRefreshSeconds = int(a.config.ServiceSpecific["route_refresh_seconds"].(float64))
	} else {
		routeRefreshSeconds = defaultRouteRefreshSeconds
	}

	if a.interhostRoutesEnabled {
		log.Infof("Agent: starting interhost routes manager")

		// Channel for stopping route update mechanism.
		stopRouteUpdater := make(chan struct{})

		// a.RouteUpdater updates routes on the current node for
		// the newly added or removed nodes in romana cluster.
		if err := a.routeUpdater(stopRouteUpdater, routeRefreshSeconds); err != nil {
			log.Errorf("Agent: Failed to start route updater on the node: %s", err)
			return err
		}
	}

	a.routec = PublishRoutesTo(a.routePublisher, a.routePublisherConfig, a.client, a.networkConfig)

	if checkFeatureSnatEnabled() {
		iptables := &iptsave.IPtables{}
		featureSnat(iptables, a.Helper.Executor, a.networkConfig)
		if err := enforcer.ApplyIPtables(iptables, a.Helper.Executor); err != nil {
			log.Errorf("Filed to install rules supporting FEATURE_SNAT iptables-restore call failed %s", err)
		}

	}

	if a.policyEnabled {
		// Tenant and Policy cache will poll backend storage every cacheTickTime seconds.
		var cacheTickTime int
		if a.config.ServiceSpecific["cache_tick_time"] != nil {
			cacheTickTime = int(a.config.ServiceSpecific["cache_tick_time"].(float64))
		} else {
			cacheTickTime = defaultCacheTickTime
		}

		// Will try to refresh policies every policyRefreshSeconds.
		var policyRefreshSeconds int
		if a.config.ServiceSpecific["policy_refresh_seconds"] != nil {
			policyRefreshSeconds = int(a.config.ServiceSpecific["policy_refresh_seconds"].(float64))
		} else {
			policyRefreshSeconds = defaultPolicyRefreshSeconds
		}

		a.policyStop = make(chan struct{})
		tenantCache := tenantCache.New(a.client, tenantCache.Config{CacheTickSeconds: cacheTickTime})
		policyCache := policyCache.New(a.client, policyCache.Config{CacheTickSeconds: cacheTickTime})
		a.enforcer = enforcer.New(tenantCache, policyCache, a.networkConfig, a.Helper.Executor, policyRefreshSeconds)
		a.enforcer.Run(a.policyStop)
	}

	return nil
}

// CreateSchema creates database schema.
func (a *Agent) CreateSchema(overwrite bool) error {
	return a.store.CreateSchema(overwrite)
}
