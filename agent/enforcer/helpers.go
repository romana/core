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

package enforcer

import (
	"bytes"
	"fmt"
	"strings"

	utilexec "github.com/romana/core/agent/exec"
	"github.com/romana/core/agent/firewall"
	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/agent/policy/hasher"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/log/trace"

	log "github.com/romana/rlog"
)

var (
	IptablesSaveBin    string
	IptablesRestoreBin string
)

// MakeIngressTenantJumpRule makes a rule to send traffic from romana ingress chain
// into a tenant specific chain.
// -A ROMANA-FORWARD-IN -m u32 --u32 "0x10&0xff00f000=0xa002000" -j ROMANA-FW-T2
func MakeIngressTenantJumpRule(tenant api.Tenant, netConfig firewall.NetConfig) *iptsave.IPrule {

	//	romanaCidr, _ := netConfig.PNetCIDR()
	//	u32TenantMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(tenant.ID).MatchDst()
	//	tenantChainName := MakeTenantIngressChainName(tenant)
	//
	//	rule := iptsave.IPrule{
	//		Match: []*iptsave.Match{
	//			&iptsave.Match{
	//				Body: fmt.Sprintf("-m u32 --u32 \"%s\"", u32TenantMatch),
	//			},
	//		},
	//		Action: iptsave.IPtablesAction{
	//			Type: iptsave.ActionOther,
	//			Body: tenantChainName,
	//		},
	//	}
	//
	//	return &rule
	return nil
}

// MakeSegmentPolicyJumpRule makes a rule to send traffic from tenant specific chain
// into a segment specific chain.
// -A ROMANA-FW-T2 -m u32 --u32 "0x10&0xff00ff00=0xa002000" -j ROMANA-T2-S0
func MakeSegmentPolicyJumpRule(tenant api.Tenant, segment api.Segment, netConfig firewall.NetConfig) *iptsave.IPrule {
	//	romanaCidr, _ := netConfig.PNetCIDR()
	//	u32SegmentMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(uint(tenant.NetworkID)).MatchSegmentId(uint(segment.NetworkID)).MatchDst()
	//	segmentChainName := MakeSegmentPolicyChainName(tenant.NetworkID, segment.NetworkID)
	//
	//	rule := iptsave.IPrule{
	//		Match: []*iptsave.Match{
	//			&iptsave.Match{
	//				Body: fmt.Sprintf("-m u32 --u32 \"%s\"", u32SegmentMatch),
	//			},
	//		},
	//		Action: iptsave.IPtablesAction{
	//			Type: iptsave.ActionOther,
	//			Body: segmentChainName,
	//		},
	//	}
	//
	//	return &rule
	return nil
}

// InsertNormalRule discovers position in a chain just above all DROP and RETURN
// rules. Useful for the rules other then default drops and chain terminators.
func InsertNormalRule(chain *iptsave.IPchain, rule *iptsave.IPrule) {
	var normalIndex int

	for i := len(chain.Rules) - 1; i >= 0; i-- {
		if chain.Rules[i].Action.Body != "DROP" && chain.Rules[i].Action.Body != "RETURN" &&
			chain.Rules[i].Action.Body != "ACCEPT" {
			normalIndex = i + 1
			break
		}
	}

	chain.InsertRule(normalIndex, rule)
}

// MakeTenantIngressChainName returns the name of iptables chain
// that holds ingress rules for specific romana tenant.
func MakeTenantIngressChainName(tenant api.Tenant) string {
	return fmt.Sprintf("ROMANA-FW-T%s", tenant.ID)
}

// MakeSegmentPolicyChainName returns the name of iptables chain
// that holds policies for specific tenant's segment.
func MakeSegmentPolicyChainName(tenantID string, segmentID string) string {
	return fmt.Sprintf("ROMANA-T%s-S%s", tenantID, segmentID)
}

// EnsureChainExists ensures that IPchain exists in IPtable.
func EnsureChainExists(table *iptsave.IPtable, chainName string) *iptsave.IPchain {
	chain := table.ChainByName(chainName)
	if chain == nil {
		chain = &iptsave.IPchain{Name: chainName, Policy: "-"}
		table.Chains = append(table.Chains, chain)
	}

	return chain
}

// MakePolicyChainFooterRule returns iptsave rule that sits at the bottom of
// a chain which hosts jumps to the romana policies.
// The rule is redaundant in many cases since default chain policy is also RETURN,
// but it highlights a flow.
func MakePolicyChainFooterRule() *iptsave.IPrule {
	rule := iptsave.IPrule{
		Match: []*iptsave.Match{
			&iptsave.Match{
				Body: "-m comment --comment POLICY_CHAIN_FOOTER",
			},
		},
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionDefault,
			Body: "RETURN",
		},
	}
	return &rule
}

// MakeTenantWideIngressChainName returns a name for iptables chain that hosts
// policies that are applied to entire tenant.
func MakeTenantWideIngressChainName(tenantID string) string {
	return fmt.Sprintf("ROMANA-T%s-W", tenantID)
}

// MakeConntrackEstablishedRule returns a rule that usually sits on top of a
// certan chain and accepts TCP packets known to iptables conntrack module.
func MakeConntrackEstablishedRule() *iptsave.IPrule {
	rule := iptsave.IPrule{
		Match: []*iptsave.Match{
			&iptsave.Match{
				Body: "-m conntrack --ctstate RELATED,ESTABLISHED",
			},
		},
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionDefault,
			Body: "ACCEPT",
		},
	}
	return &rule
}

// MakeSimpleJumpRule is a convinience function that returns ipsave.IPrule
// with no match field and single action field.
// e.g. `-j TARGET`
func MakeSimpleJumpRule(target string) *iptsave.IPrule {
	rule := iptsave.IPrule{
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionDefault,
			Body: target,
		},
	}
	return &rule
}

// MakeTenantWidePolicyJumpRule returns a rule that jumps into the iptables
// chain that hosts policies for the entire tenant.
func MakeTenantWidePolicyJumpRule(tenant api.Tenant) *iptsave.IPrule {
	return MakeSimpleJumpRule(MakeTenantWideIngressChainName(tenant.ID))
}

// MakeOperatorPolicyChainName returns the name for iptables chain
// that hosts policies applied to all tenants.
func MakeOperatorPolicyChainName() string {
	return "ROMANA-OP"
}

func MakeOperatorPolicyIngressChainName() string {
	return "ROMANA-OP-IN"
}

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

const (
	SchemePolicyOnTop = "policyOnTop"
	SchemeTargetOnTop = "targetOnTop"
)

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

// MakeRomanaPolicyIngressName returns the name of iptables chain that hosts
// one ingress field of a policy.
/*
func MakeRomanaPolicyIngressName(policy api.Policy, idx int) string {
	return fmt.Sprintf("ROMANA-P-%s-IN_%d", policy.ID, idx)
}
*/

// MakePolicyIngressJump makes jump rule from policy into policy ingress chain.
func MakePolicyIngressJump(peer api.Endpoint, targetChain string, netConfig firewall.NetConfig) *iptsave.IPrule {
	// TODO extract NetId from netConfig. Stas
	if peer.Peer == "any" || peer.Peer == "local" {
		return MakeRuleWithBody("", targetChain)
	}

	if peer.Peer == "host" {
		return MakeRuleWithBody(fmt.Sprintf("-s %s/32", netConfig.RomanaGW()), targetChain)
	}

	if peer.Cidr != "" {
		return MakeRuleWithBody(fmt.Sprintf("-s %s", peer.Cidr), targetChain)
	}

	//	romanaCidr, _ := netConfig.PNetCIDR()
	if peer.TenantID != "" && peer.SegmentID != "" {
		panic("Unimplemented")
		//		u32TenantMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(uint(*peer.TenantNetworkID)).MatchSegmentId(uint(*peer.SegmentNetworkID)).MatchSrc()
		//		return MakeRuleWithBody(fmt.Sprintf("-m u32 --u32 \"%s\"", u32TenantMatch), targetChain)
	}

	if peer.TenantID != "" {
		panic("Unimplemented")
		//		u32TenantMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(uint(*peer.TenantNetworkID)).MatchSrc()
		//		return MakeRuleWithBody(fmt.Sprintf("-m u32 --u32 \"%s\"", u32TenantMatch), targetChain)
	}

	panic("Can not render policy ingress")
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

// ValidateIPtables calls iptables-restore to validate iptables.
func ValidateIPtables(iptables *iptsave.IPtables, exec utilexec.Executable) bool {
	err := ApplyIPtables(iptables, exec, "--noflush", "--test", "-w")
	if err != nil {
		return false
	}

	return true
}

// ApplyIPtables calls iptables-restore to apply iptables.
func ApplyIPtables(iptables *iptsave.IPtables, exec utilexec.Executable, restoreFlags ...string) error {

	if restoreFlags == nil {
		restoreFlags = []string{"--noflush"}
	}

	cmd := exec.Cmd(IptablesRestoreBin, restoreFlags)
	reader := bytes.NewReader([]byte(iptables.Render()))

	log.Tracef(trace.Inside, "In applyRules allocating stdin pipe")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("Failed to allocate stdin for iptables-restore - %s", err)
	}

	log.Tracef(trace.Inside, "In applyRules starting the command")
	if err := cmd.Start(); err != nil {
		return err
	}

	log.Tracef(trace.Inside, "In applyRules sending the rules")
	_, err = reader.WriteTo(stdin)
	if err != nil {
		return err
	}

	stdin.Close()

	log.Tracef(trace.Inside, "In applyRules waiting for command to complete")
	if err := cmd.Wait(); err != nil {
		log.Tracef(trace.Inside, "In applyRules failed to apply")
		return err
	}

	return nil
}

// LoadIPtables calls iptables-save, parses result into iptsave.IPtables.
func LoadIPtables(exec utilexec.Executable) (*iptsave.IPtables, error) {
	iptables := &iptsave.IPtables{}
	rawIptablesSave, err := exec.Exec(IptablesSaveBin, []string{})
	if err != nil {
		log.Infof("In Init(), failed to call iptables-save, %s", err)
		return iptables, err
	}

	iptables.Parse(bytes.NewReader(rawIptablesSave))

	return iptables, nil
}
