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
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	utilexec "github.com/romana/core/pkg/util/exec"
	"github.com/romana/core/pkg/util/firewall"
	"github.com/romana/core/pkg/util/iptsave"
	"github.com/romana/core/pkg/util/u32"
	log "github.com/romana/rlog"
)

const (
	iptablesSaveBin    = `/sbin/iptables-save`
	iptablesRestoreBin = `/sbin/iptables-restore`
)

// MakeIngressTenantJumpRule makes a rule to send traffic from romana ingress chain
// into a tenant specific chain.
// -A ROMANA-FORWARD-IN -m u32 --u32 "0x10&0xff00f000=0xa002000" -j ROMANA-FW-T2
func MakeIngressTenantJumpRule(tenant common.Tenant, netConfig firewall.NetConfig) *iptsave.IPrule {
	romanaCidr, _ := netConfig.PNetCIDR()
	u32TenantMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(uint(tenant.NetworkID)).MatchDst()
	tenantChainName := MakeTenantIngressChainName(tenant)

	rule := iptsave.IPrule{
		Match: []*iptsave.Match{
			&iptsave.Match{
				Body: fmt.Sprintf("-m u32 --u32 \"%s\"", u32TenantMatch),
			},
		},
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionOther,
			Body: tenantChainName,
		},
	}

	return &rule
}

// MakeSegmentPolicyJumpRule makes a rule to send traffic from tenant specific chain
// into a segment specific chain.
// -A ROMANA-FW-T2 -m u32 --u32 "0x10&0xff00ff00=0xa002000" -j ROMANA-T2-S0
func MakeSegmentPolicyJumpRule(tenant common.Tenant, segment common.Segment, netConfig firewall.NetConfig) *iptsave.IPrule {
	romanaCidr, _ := netConfig.PNetCIDR()
	u32SegmentMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(uint(tenant.NetworkID)).MatchSegmentId(uint(segment.NetworkID)).MatchDst()
	segmentChainName := MakeSegmentPolicyChainName(tenant.NetworkID, segment.NetworkID)

	rule := iptsave.IPrule{
		Match: []*iptsave.Match{
			&iptsave.Match{
				Body: fmt.Sprintf("-m u32 --u32 \"%s\"", u32SegmentMatch),
			},
		},
		Action: iptsave.IPtablesAction{
			Type: iptsave.ActionOther,
			Body: segmentChainName,
		},
	}

	return &rule
}

// InsertNormalRule discovers position in a chain just above all DROP and RETURN
// rules. Useful for the rules other then default drops and chain terminators.
func InsertNormalRule(chain *iptsave.IPchain, rule *iptsave.IPrule) {
	var normalIndex int

	for i := len(chain.Rules) - 1; i >= 0; i-- {
		if chain.Rules[i].Action.Body != "DROP" && chain.Rules[i].Action.Body != "RETURN" {
			normalIndex = i + 1
			break
		}
	}

	chain.InsertRule(normalIndex, rule)
}

// MakeTenantIngressChainName returns the name of iptables chain
// that holds ingress rules for specific romana tenant.
func MakeTenantIngressChainName(tenant common.Tenant) string {
	return fmt.Sprintf("ROMANA-FW-T%d", tenant.NetworkID)
}

// MakeSegmentPolicyChainName returns the name of iptables chain
// that holds policies for specific tenant's segment.
func MakeSegmentPolicyChainName(tenantID uint64, segmentID uint64) string {
	return fmt.Sprintf("ROMANA-T%d-S%d", tenantID, segmentID)
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
func MakeTenantWideIngressChainName(tenantID uint64) string {
	return fmt.Sprintf("ROMANA-T%d-W", tenantID)
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
func MakeTenantWidePolicyJumpRule(tenant common.Tenant) *iptsave.IPrule {
	return MakeSimpleJumpRule(MakeTenantWideIngressChainName(tenant.NetworkID))
}

// MakeOperatorPolicyChainName returns the name for iptables chain
// that hosts policies applied to all tenants.
func MakeOperatorPolicyChainName() string {
	return "ROMANA-OP"
}

func MakeOperatorPolicyIngressChainName() string {
	return "ROMANA-OP-IN"
}

// PolicyTargetType represents type of common.Policy.AppliedTo.
type PolicyTargetType string

const (
	// OperatorPolicyTarget represents a policy
	// that applied to all traffic going towards pods,
	// including traffic from host.
	OperatorPolicyTarget PolicyTargetType = "operator"

	// OperatorPolicyIngressTarget represents a policy
	// that applied to traffic traveling from pods to the host.
	OperatorPolicyIngressTarget PolicyTargetType = "operator-ingress"

	// TenantWidePolicyTarget represents a policy that targets entire tenant.
	TenantWidePolicyTarget PolicyTargetType = "tenant-wide"

	// TenantSegmentPolicyTarget represents a policy that targets
	// sepcific segment withing a tenant.
	TenantSegmentPolicyTarget PolicyTargetType = "tenant-segment"

	UnknownPolicyTarget PolicyTargetType = "unknown"
)

// DetectPolicyTargetType identifies given endpoint as one of valid policy
// target types.
func DetectPolicyTargetType(target common.Endpoint) PolicyTargetType {
	if target.Dest == "local" {
		return OperatorPolicyTarget
	}

	if target.Dest == "host" {
		return OperatorPolicyIngressTarget
	}

	if target.TenantNetworkID != nil {
		if target.SegmentNetworkID != nil {
			return TenantSegmentPolicyTarget
		}

		return TenantWidePolicyTarget
	}

	return UnknownPolicyTarget
}

// MakeRomanaPolicyName returns the name of iptables chain that hosts
// policy related rules.
func MakeRomanaPolicyName(policy common.Policy) string {
	return fmt.Sprintf("ROMANA-P-%s_", policy.ExternalID)
}

// MakeRomanaPolicyIngressName returns the name of iptables chain that hosts
// one ingress field of a policy.
func MakeRomanaPolicyIngressName(policy common.Policy, idx int) string {
	return fmt.Sprintf("ROMANA-P-%s-IN_%d", policy.ExternalID, idx)
}

// MakePolicyIngressJump makes jump rule from policy into policy ingress chain.
func MakePolicyIngressJump(peer common.Endpoint, targetChain string, netConfig firewall.NetConfig) *iptsave.IPrule {
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

	romanaCidr, _ := netConfig.PNetCIDR()
	if peer.TenantNetworkID != nil && peer.SegmentNetworkID != nil {
		u32TenantMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(uint(*peer.TenantNetworkID)).MatchSegmentId(uint(*peer.SegmentNetworkID)).MatchSrc()
		return MakeRuleWithBody(fmt.Sprintf("-m u32 --u32 \"%s\"", u32TenantMatch), targetChain)
	}

	if peer.TenantNetworkID != nil {
		u32TenantMatch := u32.New(netConfig).MatchNetId(u32.IPNETtoUint(romanaCidr)).MatchTenantId(uint(*peer.TenantNetworkID)).MatchSrc()
		return MakeRuleWithBody(fmt.Sprintf("-m u32 --u32 \"%s\"", u32TenantMatch), targetChain)
	}

	panic("Can not render policy ingress")
}

// MakePolicyRule translates common.Rule into iptsave.IPrule.
func MakePolicyRule(rule common.Rule) []*iptsave.IPrule {
	var result []*iptsave.IPrule

	if rule.Protocol == "TCP" {
		if len(rule.Ports) > 0 {
			for _, port := range rule.Ports {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p tcp --dport %d", port), "ACCEPT"))
			}
		}

		if len(rule.PortRanges) > 0 {
			for _, portRange := range rule.PortRanges {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p tcp --dport %d:%d", portRange[0], portRange[1]), "ACCEPT"))
			}
		}

		if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
			result = append(result, MakeRuleDefaultWithBody("-p tcp", "ACCEPT"))
		}
	}

	if rule.Protocol == "UDP" {
		if len(rule.Ports) > 0 {
			for _, port := range rule.Ports {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p udp --dport %d", port), "ACCEPT"))
			}
		}

		if len(rule.PortRanges) > 0 {
			for _, portRange := range rule.PortRanges {
				result = append(result, MakeRuleDefaultWithBody(fmt.Sprintf("-p udp --dport %d:%d", portRange[0], portRange[1]), "ACCEPT"))
			}
		}

		if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
			result = append(result, MakeRuleDefaultWithBody("-p udp", "ACCEPT"))
		}
	}

	if rule.Protocol == "ICMP" {
		// TODO, rule.IcmpType and rule.IcmpType code can't be destinguished between
		// zero value and none value so processing them is prone to failures.
		// Need to replaces then as *uint first. Stas.
		result = append(result, MakeRuleDefaultWithBody("-p icmp", "ACCEPT"))
	}

	if rule.Protocol == "ANY" {
		// TODO, rule.IcmpType and rule.IcmpType code can't be destinguished between
		// zero value and none value so processing them is prone to failures.
		// Need to replaces then as *uint first. Stas.
		result = append(result, MakeRuleDefaultWithBody("", "ACCEPT"))
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

	cmd := exec.Cmd(iptablesRestoreBin, restoreFlags)
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
	rawIptablesSave, err := exec.Exec(iptablesSaveBin, []string{})
	if err != nil {
		log.Infof("In Init(), failed to call iptables-save, %s", err)
		return iptables, err
	}

	iptables.Parse(bytes.NewReader(rawIptablesSave))

	return iptables, nil
}
