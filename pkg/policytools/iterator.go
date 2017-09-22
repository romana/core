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

package policytools

import (
	"fmt"

	"github.com/romana/core/common/api"
)

// PolicyIterator provides a way to iterate over every combination of a
// target * peer * rule in a list of policies.
type PolicyIterator struct {
	policies   []api.Policy
	policyIdx  int
	targetIdx  int
	ingressIdx int
	peerIdx    int
	ruleIdx    int
	started    bool
}

// New creates a new PolicyIterator.
func NewPolicyIterator(policies []api.Policy) (*PolicyIterator, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("must have non empty policies list")
	}

	return &PolicyIterator{policies: policies}, nil
}

// Next advances policy iterator to the next combination
// of policy * target * peer * rule. It returns false if iterator
// can not advance any further, otherwise it returs true.
func (i *PolicyIterator) Next() bool {
	if !i.started {
		i.started = true
		return true
	}

	policy, _, ingress, _, _ := i.items()

	if i.ruleIdx < len(ingress.Rules)-1 {
		i.ruleIdx += 1
		return true
	}

	if i.peerIdx < len(ingress.Peers)-1 {
		i.peerIdx += 1
		i.ruleIdx = 0
		return true
	}

	if i.ingressIdx < len(policy.Ingress)-1 {
		i.ingressIdx += 1
		i.ruleIdx = 0
		i.peerIdx = 0
		return true
	}

	if i.targetIdx < len(policy.AppliedTo)-1 {
		i.targetIdx += 1
		i.ingressIdx = 0
		i.ruleIdx = 0
		i.peerIdx = 0
		return true
	}

	if i.policyIdx < len(i.policies)-1 {
		i.policyIdx += 1
		i.targetIdx = 0
		i.ingressIdx = 0
		i.ruleIdx = 0
		i.peerIdx = 0
		return true
	}

	return false
}

// Items retrieves current combination of policy * target * peer * rule from iterator.
func (i PolicyIterator) Items() (api.Policy, api.Endpoint, api.Endpoint, api.Rule) {
	policy, target, _, peer, rule := i.items()
	return policy, target, peer, rule
}

func (i PolicyIterator) items() (api.Policy, api.Endpoint, api.RomanaIngress, api.Endpoint, api.Rule) {
	policy := i.policies[i.policyIdx]
	target := policy.AppliedTo[i.targetIdx]
	ingress := policy.Ingress[i.ingressIdx]
	peer := policy.Ingress[i.ingressIdx].Peers[i.peerIdx]
	rule := policy.Ingress[i.ingressIdx].Rules[i.ruleIdx]
	return policy, target, ingress, peer, rule
}
