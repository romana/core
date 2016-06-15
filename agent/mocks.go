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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// mocks.go contins Helper structure with interfaces which which is used
// to interact with operation system.
//
// - OS interface used to access filesystem, write and read files.
// - Executable interface is used to execute commands in operation system.
//
// Both interfaces has default and fake implementations, default implementation
// will usually just proxy calls to standard library while test implemetation
// will allow mocking all interactions.

package agent

import (
	"net"
	"sync"

	"github.com/romana/core/common"
	utilexec "github.com/romana/core/pkg/util/exec"
	utilos "github.com/romana/core/pkg/util/os"
)

// TODO There is a tradeoff, either use global variable for provider
// or pass provider down to each method.
// Passing down to each method is more explicit which is good,
// but pollutes methods' signatures too much. Need to have a discussion.

// Helper groups testable implementations
// of standard library functions.
type Helper struct {
	Executor                   utilexec.Executable
	OS                         utilos.OS
	Agent                      *Agent //access field for Agent
	ensureRouteToEndpointMutex *sync.Mutex
	ensureLineMutex            *sync.Mutex
	ensureInterHostRoutesMutex *sync.Mutex
}

// mockAgent creates the agent with the configuration
// needed for tests without the need to go through
// configuration files.
func mockAgent() Agent {

	host0 := common.HostMessage{Ip: "172.17.0.1", RomanaIp: "127.0.0.1/8"}

	// romanaIP, romanaNet, _ := net.ParseCIDR(host0.RomanaIp)

	networkConfig := &NetworkConfig{}
	networkConfig.romanaGW = net.ParseIP(host0.Ip)

	host1 := common.HostMessage{Ip: "192.168.0.12", RomanaIp: "10.65.0.0/16"}
	networkConfig.otherHosts = []common.HostMessage{host1}

	dc := common.Datacenter{}
	dc.Cidr = "10.0.0.0/8"
	dc.PortBits = 8
	dc.TenantBits = 4
	dc.SegmentBits = 4
	dc.EndpointSpaceBits = 0
	dc.EndpointBits = 8

	networkConfig.dc = dc
	agent := &Agent{networkConfig: networkConfig}
	helper := NewAgentHelper(agent)
	agent.Helper = &helper

	storeConfig := common.ServiceConfig{ServiceSpecific: map[string]interface{}{
		"type":     "sqlite3",
		"database": "/tmp/agent.db"}}
	agent.store = agentStore{}
	agent.store.ServiceStore = &agent.store
	agent.store.SetConfig(storeConfig.ServiceSpecific)

	agent.createSchema(true) // overwrite

	return *agent
}
