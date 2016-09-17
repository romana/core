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

import (
)

// RuleSet is a collection of agent rules.
type RuleSet []Rule

// Rule type in romana agent represents a firewall rule
// along with information about how this rule should be
// provisioned in firewall.
type Rule struct {
	// Specifies what kind of formatting must
	// be applied to the Body of the rule.
	Format RuleFormat

	// Text representation of the rule.
	Body string

	// Specifies what position rule must occupy.
	Position RulePosition

	// Specifies traffic direction the rule must be applied to.
	Direction RuleDirection
}

type RuleFormat int

const (
	NoFormatNeeded RuleFormat = iota
	FormatChain
	FormatChainU32TenantSegment
)

type RulePosition int

const (
	DefaultPosition RulePosition = iota
	TopPosition
	BottomPosition
)

type RuleDirection int

const (
	// List of rules matching traffic form endpoints to the host.
	EgressLocalDirection RuleDirection = iota

	// List of rules matching traffic from endpoints to the rest
	// of the world.
	EgressGlobalDirection

	// List of rules matching traffic from the host to the endpoints.
	IngressLocalDirection

	// List of rules matching traffic from the world to the endpoints.
	IngressGlobalDirection
)

// KubeShellRules is a set of rules to be applied for kubernetes with ShellexProvider firewall.
var KubeShellRules = RuleSet{
		Rule{
			Format: FormatChain,
			Body: "%s -m comment --comment DefaultDrop -j DROP",
			Position: DefaultPosition,
			Direction: EgressLocalDirection,
		},
		Rule{
			Format: FormatChain,
			Body: "%s -m state --state ESTABLISHED -j ACCEPT",
			Position: DefaultPosition,
			Direction: EgressLocalDirection,
		},
		Rule{
			Format: FormatChain,
			Body: "%s -m comment --comment Outgoing -j RETURN",
			Position: DefaultPosition,
			Direction: EgressGlobalDirection,
		},
		Rule{
			Format: FormatChain,
			Body: "%s -m state --state RELATED,ESTABLISHED -j ACCEPT",
			Position: DefaultPosition,
			Direction: IngressGlobalDirection,
		},
}

var KubeSaveRestoreRules = RuleSet{
		Rule{
			Format: FormatChain,
			Body: "%s -m comment --comment DefaultDrop -j DROP",
			Position: BottomPosition,
			Direction: EgressLocalDirection,
		},
		Rule{
			Format: FormatChain,
			Body: "%s -m state --state ESTABLISHED -j ACCEPT",
			Position: TopPosition,
			Direction: EgressLocalDirection,
		},
		Rule{
			Format: FormatChain,
			Body: "%s -m comment --comment Outgoing -j RETURN",
			Position: TopPosition,
			Direction: EgressGlobalDirection,
		},
		Rule{
			Format: FormatChain,
			Body: "%s -m state --state RELATED,ESTABLISHED -j ACCEPT",
			Position: TopPosition,
			Direction: IngressGlobalDirection,
		},
}
