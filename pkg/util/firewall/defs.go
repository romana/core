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
	"fmt"
)

// Firewall interface allows different implementation to be used with
// romana agent.
type Firewall interface {
	// Init initializes firewall.
	Init(utilexec.Executable, FirewallStore, NetConfig) error

	// SetEndpoint prepares firewall instance for using ProvisionEndpoint method.
	SetEndpoint(FirewallEndpoint) error

	// SetDefaultRules allows to inject a set of rules to be installed during
	// ProvisionEndpoint run.
	SetDefaultRules([]FirewallRule) error

	// ProvisionEndpoint generates and applies rules for given endpoint.
	// Make sure to run SetEndpoint first.
	ProvisionEndpoint() error

	// EnsureRule checks if specified rule in desired state.
	EnsureRule(FirewallRule, RuleState) error

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

// NewFirewall returns instance of Firewall backed by requested provider
func NewFirewall(provider Provider) (Firewall, error) {
	var fw Firewall

	switch provider {
	case IPTsaveProvider:
		fw = new(IPTsaveFirewall)
	default:
		fw = new(IPtables)
	}

	return fw, nil
}

// Provider represents a type of firewall implementation.
type Provider int

const (
	// shellex is a default firewall implementation
	// based on line-by-line firewall provisioning
	ShellexProvider Provider = iota

	// iptsave is an implementation of firewall
	// based on iptables-save/iptabels-restore
	IPTsaveProvider
)

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
	EnsureLast RuleState = iota
	EnsureFirst
	EnsureAbsent
)

func (i RuleState) String() string {
	var result string
	switch i {
	case EnsureLast:
		result = "Ensuring rule at the bottom"
	case EnsureFirst:
		result = "Ensuring rule at the top"
	case EnsureAbsent:
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
