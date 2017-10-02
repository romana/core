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

//go:generate go run internal/gen/main.go -data data/policy.tsv -template templates/blueprint.go_template -out blueprint_table.go

package policytools

import (
	"fmt"
	"strings"

	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/agent/policy/hasher"
	"github.com/romana/core/common/api"
	"github.com/romana/rlog"
)

type RuleBlueprint struct {
	BaseChain        string
	TopRuleMatch     func(api.Endpoint) string
	TopRuleAction    func(api.Policy) string
	SecondBaseChain  func(api.Policy) string
	SecondRuleMatch  func(api.Endpoint) string
	SecondRuleAction func(api.Policy) string
	ThirdBaseChain   func(api.Policy) string
	ThirdRuleMatch   func(api.Endpoint) string
	ThirdRuleAction  func(api.Policy) string
	FourthBaseChain  func(api.Policy) string
	FourthRuleMatch  func(api.Rule, string) []*iptsave.IPrule
	FourthRuleAction string
}

func MakeBlueprintKey(direction, iptablesSchemeType string, peerType PolicyPeerType, targetType PolicyTargetType) string {

	var result string
	switch direction {
	case api.PolicyDirectionIngress:
		result = fmt.Sprintf("ingress_%s_from_%s_to_%s_", iptablesSchemeType, peerType, targetType)
	case api.PolicyDirectionEgress:
		result = fmt.Sprintf("egress_%s_from_%s_to_%s_", iptablesSchemeType, targetType, peerType)
	}

	return result
}

const (
	SchemePolicyOnTop     = "policyOnTop"
	SchemeTargetOnTop     = "targetOnTop"
	DefaultIptablesSchema = SchemePolicyOnTop
)

// PolicyPeerType represents type of api.Policy.AppliedTo.
type PolicyPeerType string

const (
	PeerHost          PolicyPeerType = "peerHost"
	PeerLocal         PolicyPeerType = "peerLocal"
	PeerTenant        PolicyPeerType = "peerTenant"
	PeerTenantSegment PolicyPeerType = "peerTenantSegment"
	PeerCIDR          PolicyPeerType = "peerCidr"
	PeerAny           PolicyPeerType = "peerAny"
	PeerUnknown       PolicyPeerType = "peerUnknown"
)

func DetectPolicyPeerType(peer api.Endpoint) PolicyPeerType {
	if peer.Peer == "local" {
		return PeerLocal
	}

	if peer.Peer == "host" {
		return PeerHost
	}

	if peer.Peer == "any" {
		return PeerAny
	}

	if peer.Cidr != "" {
		return PeerCIDR
	}

	if peer.TenantID != "" {
		if peer.SegmentID != "" {
			return PeerTenantSegment
		}

		return PeerTenant
	}

	return PeerUnknown

}

// PolicyTargetType represents type of api.Policy.AppliedTo.
type PolicyTargetType string

const (
	// OperatorPolicyTarget represents a policy
	// that applied to all traffic going towards pods,
	// including traffic from host.
	OperatorPolicyTarget PolicyTargetType = "operator"

	// OperatorPolicyIngressTarget represents a policy
	// that applied to traffic traveling from pods to the host.
	OperatorPolicyIngressTarget PolicyTargetType = "operatorIngress"

	// TenantWidePolicyTarget represents a policy that targets entire tenant.
	TenantWidePolicyTarget PolicyTargetType = "tenantWide"

	// TenantSegmentPolicyTarget represents a policy that targets
	// sepcific segment withing a tenant.
	TenantSegmentPolicyTarget PolicyTargetType = "tenantSegment"

	TargetHost          PolicyTargetType = "targetHost"
	TargetLocal         PolicyTargetType = "targetLocal"
	TargetTenant        PolicyTargetType = "targetTenant"
	TargetTenantSegment PolicyTargetType = "targetTenantSegment"

	UnknownPolicyTarget PolicyTargetType = "unknown"
)

// DetectPolicyTargetType identifies given endpoint as one of valid policy
// target types.
func DetectPolicyTargetType(target api.Endpoint) PolicyTargetType {
	if target.Dest == "local" {
		return TargetLocal
	}

	if target.Dest == "host" {
		return TargetHost
	}

	if target.TenantID != "" {
		if target.SegmentID != "" {
			return TargetTenantSegment
		}

		return TargetTenant
	}

	return UnknownPolicyTarget
}

// MakeRomanaPolicyName returns the name of iptables chain that hosts
// policy related rules.
func MakeRomanaPolicyName(policy api.Policy) string {
	hash := hasher.HashRomanaPolicy(policy)
	return fmt.Sprintf("ROMANA-P-%s", hash[:16])
}

func MakeRomanaPolicyNameExtended(policy api.Policy) string {
	return fmt.Sprintf("%s_X", MakeRomanaPolicyName(policy))
}

func MakeRomanaPolicyNameRules(policy api.Policy) string {
	return fmt.Sprintf("%s_R", MakeRomanaPolicyName(policy))
}

func MakeRomanaPolicyNameSetSrc(policy api.Policy) string {
	return fmt.Sprintf("%s_s", MakeRomanaPolicyName(policy))
}

func MakeRomanaPolicyNameSetDst(policy api.Policy) string {
	return fmt.Sprintf("%s_d", MakeRomanaPolicyName(policy))
}

// MakePolicyRule translates common.Rule into iptsave.IPrule.
func MakePolicyRule(rule api.Rule) []*iptsave.IPrule {
	return MakePolicyRuleWithAction(rule, "ACCEPT")
}

func MakePolicyRuleWithAction(rule api.Rule, action string) []*iptsave.IPrule {
	var result []*iptsave.IPrule

	if strings.ToUpper(rule.Protocol) == "TCP" {
		if len(rule.Ports) > 0 {
			for _, port := range rule.Ports {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p tcp --dport %d", port), action))
			}
		}

		if len(rule.PortRanges) > 0 {
			for _, portRange := range rule.PortRanges {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p tcp --dport %d:%d", portRange[0], portRange[1]), action))
			}
		}

		if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
			result = append(result, MakeRuleDefaultWithBody("-p tcp", action))
		}
	}

	if strings.ToUpper(rule.Protocol) == "UDP" {
		if len(rule.Ports) > 0 {
			for _, port := range rule.Ports {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p udp --dport %d", port), action))
			}
		}

		if len(rule.PortRanges) > 0 {
			for _, portRange := range rule.PortRanges {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p udp --dport %d:%d", portRange[0], portRange[1]), action))
			}
		}

		if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
			result = append(result, MakeRuleDefaultWithBody("-p udp", action))
		}
	}

	if strings.ToUpper(rule.Protocol) == "ICMP" {
		// TODO, rule.IcmpType and rule.IcmpType code can't be destinguished between
		// zero value and none value so processing them is prone to failures.
		// Need to replaces then as *uint first. Stas.
		result = append(result, MakeRuleDefaultWithBody("-p icmp", action))
	}

	if strings.ToUpper(rule.Protocol) == "ANY" {
		// TODO, rule.IcmpType and rule.IcmpType code can't be destinguished between
		// zero value and none value so processing them is prone to failures.
		// Need to replaces then as *uint first. Stas.
		result = append(result, MakeRuleDefaultWithBody("", action))
	}
	return result
}

func MakeSrcTenantMatch(e api.Endpoint) string { return makeTenantMatch(e, "src") }
func MakeDstTenantMatch(e api.Endpoint) string { return makeTenantMatch(e, "dst") }
func makeTenantMatch(e api.Endpoint, direction string) string {
	return fmt.Sprintf("-m set --match-set %s %s", MakeTenantSetName(e.TenantID, ""), direction)
}

func MakeSrcTenantSegmentMatch(e api.Endpoint) string { return makeTenantSegmentMatch(e, "src") }
func MakeDstTenantSegmentMatch(e api.Endpoint) string { return makeTenantSegmentMatch(e, "dst") }
func makeTenantSegmentMatch(e api.Endpoint, direction string) string {
	return fmt.Sprintf("-m set --match-set %s %s", MakeTenantSetName(e.TenantID, e.SegmentID), direction)
}

func MakeSrcCIDRMatch(e api.Endpoint) string { return makeCIDRMatch(e, "s") }
func MakeDstCIDRMatch(e api.Endpoint) string { return makeCIDRMatch(e, "d") }
func makeCIDRMatch(e api.Endpoint, direction string) string {
	return fmt.Sprintf("-%s %s", direction, e.Cidr)
}

func MatchEndpoint(s string) func(api.Endpoint) string {
	return func(api.Endpoint) string { return s }
}
func MatchPolicyString(s string) func(api.Policy) string {
	return func(api.Policy) string { return s }
}

// MakeRuleWithBody is a convinience function that returns a simple iptsave.IPrule
// with one match and one action.
func MakeRuleWithBody(body string, target string) *iptsave.IPrule {
	rule := iptsave.IPrule{
		Match: []*iptsave.Match{
			&iptsave.Match{
				Body: body,
			},
		},
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionOther,
			Body: target,
		},
	}

	return &rule
}

// MakeRuleDefaultWithBody is a convinience function that returns a simple iptsave.IPrule
// with one match and one default (e.g. ACCEPT,DROP,RETURN) action.
func MakeRuleDefaultWithBody(body string, target string) *iptsave.IPrule {
	rule := iptsave.IPrule{
		Match: []*iptsave.Match{
			&iptsave.Match{
				Body: body,
			},
		},
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionDefault,
			Body: target,
		},
	}

	return &rule
}

func MakeTenantSetName(tenant, segment string) string {
	setName := fmt.Sprintf("tenant_%s", tenant)
	if segment != "" {
		setName += fmt.Sprintf("_segment_%s", segment)
	}
	hash := hasher.HashListOfStrings([]string{setName})

	rlog.Debugf("In makeTenantSetName(%s, %s) out with %s",
		tenant, segment, "ROMANA-"+hash[:16])

	return "ROMANA-" + hash[:16]
}
