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
// This file store default rules that should be applied by the agent
// when it doesn endpoint proisioning.
// TODO Eventually agent should just load this rules from provided location
// for now they just hardcoded in this file.

package agent

import ()

// Rule type in romana agent represents a firewall rule
// along with information about how this rule should be
// provisioned in firewall.
type Rule struct {
	// Text representation of the rule may contain
	// dynamic tokens (%s), this flag tells how to
	// expand such tokens.
	Format RuleFormat

	// Text representation of the rule.
	Body string

	// Specifies what position rule must occupy.
	// Provides a hint for firewall on how to
	// install this rule in relation to other rules.
	// e.g. top, bottom, after/before something.
	Position RulePosition

	// Specifies traffic direction the rule must be applied to.
	// Provides a hint for firewall on rule placement,
	// different firewall implementations might interpret it
	// differently.
	Direction RuleDirection
}

// RuleSet is a collection of agent rules.
type RuleSet []Rule

// RuleFormat indicates that Rule.Body contains a specific
// number of tokens that should be replaced with specific
// information.
type RuleFormat int

const (
	NoFormatNeeded RuleFormat = iota

	// There is one token in the rule which
	// must be replaced with a chain iptables
	// chain name.
	FormatChain

	// There are 3 tokens in the rule
	// first one must be replaced with iptables
	// chain name, second one must be replaced
	// with localhost ip address (e.g. 10.1.0.1)
	// and a last one with u32 mask that
	// matches romana tenant and segment.
	FormatChainHostU32TenantSegment
)

// RulePosition indicates that firewall implementation
// should render the rule at specific place of the ruleset
// e.g. in iptables chain.
type RulePosition int

const (
	// Firewall implementation uses default
	// position for the rule.
	DefaultPosition RulePosition = iota

	// Firewall implementation should put
	// this rule at the top of the chain/list.
	TopPosition

	// Firewall implementation should put
	// this rule at the bottom of the chain/list.
	BottomPosition
)

// RuleDirection indicates that rule should be applied to the traffic
// going in a specific direction.
type RuleDirection int

const (
	// List of rules matching traffic from endpoints to the host.
	EgressLocalDirection RuleDirection = iota

	// List of rules matching traffic from endpoints to the rest
	// of the world.
	EgressGlobalDirection

	// List of rules matching traffic from the host to the endpoints.
	IngressLocalDirection

	// List of rules matching traffic from the world to the endpoints.
	IngressGlobalDirection
)

// We support different firewall implementation backends (currently ShellxProvider and IPTsaveProvider).
// Different providers may use different strategies for placing and ordering rules. Furthermore, different
// orchestration systems (such as Kubernetes or OpenStack) have different requirements for the rules
// they need and for how rules are inserted.
// Therefore, we need to provide separate and specific rule specifications for each provider in the context
// of each orchestration environment. Below then, we have these specifications.

// KubeShellXRules is a set of rules to be applied for kubernetes with ShellexProvider firewall.
var KubeShellXRules = RuleSet{
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment DefaultDrop -j DROP",
		Position:  DefaultPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state ESTABLISHED -j ACCEPT",
		Position:  DefaultPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment Outgoing -j RETURN",
		Position:  DefaultPosition,
		Direction: EgressGlobalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state RELATED,ESTABLISHED -j ACCEPT",
		Position:  DefaultPosition,
		Direction: IngressGlobalDirection,
	},
}

// KubeSaveRestoreRules is a set of rules to be applied for kubernetes with IPTsaveProvider firewall.
var KubeSaveRestoreRules = RuleSet{
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment DefaultDrop -j DROP",
		Position:  BottomPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state ESTABLISHED -j ACCEPT",
		Position:  TopPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment Outgoing -j RETURN",
		Position:  TopPosition,
		Direction: EgressGlobalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state RELATED,ESTABLISHED -j ACCEPT",
		Position:  TopPosition,
		Direction: IngressGlobalDirection,
	},
}

// OpenStackShellRules is a set of rules to be applied for OpenStack with ShellexProvider firewall.
var OpenStackShellRules = RuleSet{
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment DefaultDrop -j DROP",
		Position:  DefaultPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state ESTABLISHED -j ACCEPT",
		Position:  DefaultPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment Outgoing -j RETURN",
		Position:  DefaultPosition,
		Direction: EgressGlobalDirection,
	},
	Rule{
		Format:    FormatChainHostU32TenantSegment,
		Body:      "%s ! -s %s -m u32 --u32 %s -j ACCEPT",
		Position:  DefaultPosition,
		Direction: IngressGlobalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state RELATED,ESTABLISHED -j ACCEPT",
		Position:  DefaultPosition,
		Direction: IngressGlobalDirection,
	},
}

// OpenStackSaveRestoreRules is a set of rules to be applied for OpenStack with IPTsaveProvider firewall.
var OpenStackSaveRestoreRules = RuleSet{
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment DefaultDrop -j DROP",
		Position:  BottomPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state ESTABLISHED -j ACCEPT",
		Position:  TopPosition,
		Direction: EgressLocalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m comment --comment Outgoing -j RETURN",
		Position:  BottomPosition,
		Direction: EgressGlobalDirection,
	},
	Rule{
		Format:    FormatChainHostU32TenantSegment,
		Body:      "%s ! -s %s -m u32 --u32 %s -j ACCEPT",
		Position:  TopPosition,
		Direction: IngressGlobalDirection,
	},
	Rule{
		Format:    FormatChain,
		Body:      "%s -m state --state RELATED,ESTABLISHED -j ACCEPT",
		Position:  TopPosition,
		Direction: IngressGlobalDirection,
	},
}
