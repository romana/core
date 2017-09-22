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
	"strings"

	"github.com/romana/core/common/api"
)

// isValidProto checks if the Protocol specified in Rule is valid.
// The following protocols are recognized:
// - any -- see Wildcard
// - tcp
// - udp
// - icmp
func isValidProto(proto string) bool {
	switch proto {
	case "icmp", "tcp", "udp":
		return true
	// Wildcard
	case api.Wildcard:
		return true
	}
	return false
}

// validate validates Rule.
func validateRule(r api.Rule) []string {
	var errMsg []string
	ruleNo := 0

	r.Protocol = strings.TrimSpace(strings.ToLower(r.Protocol))
	if r.Protocol == "" {
		errMsg = append(errMsg, fmt.Sprintf("Rule #%d: No protocol specified.", ruleNo))
	} else if !isValidProto(r.Protocol) {
		errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid protocol: %s.", ruleNo, r.Protocol))
	}

	if r.Protocol == "tcp" || r.Protocol == "udp" {
		badRanges := make([]string, 0)
		for _, portRange := range r.PortRanges {
			if portRange[0] > portRange[1] || portRange[0] > api.MaxPortNumber || portRange[1] > api.MaxPortNumber {
				badRanges = append(badRanges, portRange.String())
			}
		}
		if len(badRanges) > 0 {
			errMsg = append(errMsg, fmt.Sprintf("Rule #%d: The following port ranges are invalid: %s.", ruleNo, strings.Join(badRanges, ", ")))
		}
		badPorts := make([]string, 0)
		for _, port := range r.Ports {
			if port > api.MaxPortNumber {
				badPorts = append(badPorts, fmt.Sprintf("%d", port))
			}
		}
		if len(badPorts) > 0 {
			errMsg = append(errMsg, fmt.Sprintf("Rule #%d: The following ports are invalid: %s.", ruleNo, strings.Join(badPorts, ", ")))
		}
	}
	if r.Protocol != "icmp" {
		if r.IcmpCode > 0 || r.IcmpType > 0 {
			errMsg = append(errMsg, fmt.Sprintf("Rule #%d: ICMP protocol is not specified but ICMP Code and/or ICMP Type are also specified.", ruleNo))
		}
	} else {
		if len(r.Ports) > 0 || len(r.PortRanges) > 0 {
			errMsg = append(errMsg, fmt.Sprintf("Rule #%d: ICMP protocol is specified but ports are also specified.", ruleNo))
		}
		if r.IcmpType > api.MaxIcmpType {
			errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP type: %d.", ruleNo, r.IcmpType))
		}
		switch r.IcmpType {
		case 3: // Destination unreachable
			if r.IcmpCode > 15 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
			}
		case 4: // Source quench
			if r.IcmpCode != 0 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
			}
		case 5: // Redirect
			if r.IcmpCode > 3 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
			}
		case 11: // Time exceeded
			if r.IcmpCode > 1 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
			}
		default:
			if r.IcmpCode != 0 {
				errMsg = append(errMsg, fmt.Sprintf("Rule #%d: Invalid ICMP code for type %d: %d.", ruleNo, r.IcmpType, r.IcmpCode))
			}
		}
	}
	return errMsg
}

// Validate validates the policy and returns an Unprocessable Entity (422) HttpError if the policy
// is invalid. The following would lead to errors if they are not specified elsewhere:
func ValidatePolicy(policy api.Policy) error {
	toList := func(p ...api.Policy) []api.Policy { return p }

	iterator, err := NewPolicyIterator(toList(policy))
	if err != nil {
		return err
	}

	for iterator.Next() {
		p, target, peer, rule := iterator.Items()

		peerType := DetectPolicyPeerType(peer)
		targetType := DetectPolicyTargetType(target)

		blueprintKey := MakeBlueprintKey(p.Direction, DefaultIptablesSchema, peerType, targetType)
		_, ok := Blueprints[blueprintKey]
		if !ok {
			return fmt.Errorf("invalid combination of target=%s, peer=%s, direction=%s",
				peer, target, p.Direction)
		}

		errMsg := validateRule(rule)
		if errMsg != nil {
			return fmt.Errorf("invalid rule %s", errMsg)
		}

	}

	return nil
}
