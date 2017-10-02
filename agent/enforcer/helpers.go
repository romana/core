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

	utilexec "github.com/romana/core/agent/exec"
	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/common/log/trace"

	log "github.com/romana/rlog"
)

var (
	IptablesSaveBin    string
	IptablesRestoreBin string
)

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

// MakeOperatorPolicyChainName returns the name for iptables chain
// that hosts policies applied to all tenants.
func MakeOperatorPolicyChainName() string {
	return "ROMANA-OP"
}

func MakeOperatorPolicyIngressChainName() string {
	return "ROMANA-OP-IN"
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
