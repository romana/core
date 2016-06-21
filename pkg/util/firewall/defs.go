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
// This file contains structures exported by the firewall package

package firewall

import (
	utilexec "github.com/romana/core/pkg/util/exec"
	"net"
)

// Firewall interface allows different implementation to be used with
// romana agent.
type Firewall interface {
	// ProvisionEndpoint generates and applies rules for given endpoint.
	ProvisionEndpoint(netif FirewallEndpoint) error

	// EnsureRule checks if specified rule in desired state.
	EnsureRule(ruleSpec []string, op RuleState) error

	// ListRules returns a list of firewall rules.
	ListRules() ([]IPtablesRule, error)

	// Cleanup deletes DB records and uninstall rules associated with given endpoint.
	Cleanup(netif FirewallEndpoint) error
}

// NetConfig is for agent.NetworkConfig.
type NetConfig interface {
	PNetCIDR() (cidr *net.IPNet, err error)
	TenantBits() uint
	SegmentBits() uint
	EndpointBits() uint
	EndpointNetmaskSize() uint64
	RomanaGW() net.IP
}

// NewFirewall returns fully initialized firewall struct, with rules and chains
// configured for given endpoint.
func NewFirewall(executor utilexec.Executable, store FirewallStore, nc NetConfig, env FirewallEnvironment) (Firewall, error) {

	fwstore := firewallStore{}
	fwstore.DbStore = store.GetDb()
	fwstore.mu = store.GetMutex()

	fw := new(IPtables)
	fw.Store = fwstore
	fw.os = executor
	fw.Environment = env
	fw.networkConfig = nc

	return *fw, nil
}

// FirewallEnvironment used as a parameter in the environment aware functions
// of the package.
type FirewallEnvironment int

const (
	KubernetesEnvironment FirewallEnvironment = iota
	OpenStackEnvironment
)

func (fp FirewallEnvironment) String() string {
	var result string
	switch fp {
	case KubernetesEnvironment:
		return "Kubernetes"
	case OpenStackEnvironment:
		return "OpenStack"
	}

	return result
}

// RuleState is a parameter for ensureIPtablesRule function
// which describes desired state of firewall rule.
type RuleState int

const (
	ensureLast RuleState = iota
	ensureFirst
	ensureAbsent
)

func (i RuleState) String() string {
	var result string
	switch i {
	case ensureLast:
		result = "Ensuring rule at the bottom"
	case ensureFirst:
		result = "Ensuring rule at the top"
	case ensureAbsent:
		result = "Ensuring rule is absent"
	}

	return result
}

// FirewallEndpoint is an interface for agent to pass endpoint definition.
type FirewallEndpoint interface {
	GetMac() string
	GetIP() net.IP
	GetName() string
}
