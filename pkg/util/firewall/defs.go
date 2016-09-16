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
	"fmt"
	"net"

	utilexec "github.com/romana/core/pkg/util/exec"
)

// Firewall interface allows different implementation to be used with
// romana agent.
type Firewall interface {
	// Init prepares firewall instance for using ProvisionEndpoint method.
	Init(FirewallEndpoint) error

	// SetDefaultRules allows to inject a set of rules to be installed during
	// ProvisionEndpoint run.
	SetDefaultRules([]FirewallRule) error

	// ProvisionEndpoint generates and applies rules for given endpoint.
	// Make sure to run Init first.
	ProvisionEndpoint() error

	// EnsureRule checks if specified rule in desired state.
	EnsureRule(*IPtablesRule, RuleState) error

	// Metadata provides access to the metadata associated with current instance of firewall.
	// Access method, does not require Init.
	Metadata() map[string]interface{}

	// Provider is a name of current firewall implementation.
	// Allows package users to implement behaviour specific
	// for firewall type e.g. special rules format for iptables.
	// Access method, does not require Init.
	Provider() string

	// ListRules returns a list of firewall rules.
	// Access method, does not require Init.
	ListRules() ([]IPtablesRule, error)

	// Cleanup deletes DB records and uninstall rules associated with given endpoint.
	// Does not require Init.
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
func NewFirewall(executor utilexec.Executable, store FirewallStore, nc NetConfig) (Firewall, error) {

	fwstore := firewallStore{}
	fwstore.DbStore = store.GetDb()
	fwstore.mu = store.GetMutex()

	fw := new(IPtables)
	fw.Store = fwstore
	fw.os = executor
	fw.networkConfig = nc

	return fw, nil
}

// ChainState is a parameter for ensureIPtablesChain function
// which describes desired state of firewall rule.
type chainState int

const (
	ensureChainExists chainState = iota
	ensureChainAbsent
)

func (i chainState) String() string {
	var result string
	switch i {
	case ensureChainExists:
		result = "Ensuring iptables chain exists"
	case ensureChainAbsent:
		result = "Ensuring iptables chain is absent"
	default:
		result = fmt.Sprintf("Unknown desired state code=%d for the iptables chain", i)
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

// FirewallRule is an interface that represents abstract firewall rule.
// Firewall users should use it to inject rules into the firewall.
type FirewallRule interface {
	GetBody() string
	SetBody(string)
	GetType() string
}

// NewFirewallrule returns firewall rule of appropriate type.
func NewFirewallRule() FirewallRule {
	return new(IPtablesRule)
}
