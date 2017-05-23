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
//
// iptsave.go contains firewall implementation based on iptsave package

package firewall

import (
	"bytes"
	"fmt"

	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/common/log/trace"
	utilexec "github.com/romana/core/pkg/util/exec"

	log "github.com/romana/rlog"
)

const (
	iptablesSaveBin    = `/sbin/iptables-save`
	iptablesRestoreBin = `/sbin/iptables-restore`
)

// IPTsaveFirewall implements romana Firewall using iptables-save|iptables-restore.
type IPTsaveFirewall struct {
	u32filter     string
	chainPrefix   string
	interfaceName string

	CurrentState *iptsave.IPtables
	DesiredState *iptsave.IPtables
	Store        firewallStore
	newRules     []IPtablesRule

	os utilexec.Executable

	// Discovered run-time configuration.
	networkConfig NetConfig
}

// Init implements Firewall interface
func (i *IPTsaveFirewall) Init(exec utilexec.Executable, store FirewallStore, nc NetConfig) error {

	fwstore := firewallStore{}
	fwstore.RdbmsStore = store.GetDb()
	fwstore.mu = store.GetMutex()

	i.Store = fwstore
	i.os = exec
	i.networkConfig = nc

	// Read current iptables config.
	output, err := i.os.Exec(iptablesSaveBin, []string{})
	if err != nil {
		log.Errorf("In Init(), failed to call iptables-save, %s", err)
		return err
	}

	// Parse iptables-save output.
	i.CurrentState = &iptsave.IPtables{}
	i.CurrentState.Parse(bytes.NewReader(output))

	// Inirialize desired state filter table.
	i.DesiredState = &iptsave.IPtables{}
	i.DesiredState.Tables = append(i.DesiredState.Tables, &iptsave.IPtable{Name: "filter"})
	log.Tracef(trace.Inside, "In Init(), iptables rules loaded\n, %s", i.CurrentState.Render())

	return nil
}

// SetEndpoint implements Firewall interface. It initializes
// endpoint dependend values of firewall.
func (i *IPTsaveFirewall) SetEndpoint(netif FirewallEndpoint) error {
	log.Infof("In SetEndpoint() with endpoint <iface=%s, ip=%s, mac=%s>", netif.GetName(), netif.GetIP(), netif.GetMac())

	var err error
	i.interfaceName = netif.GetName()

	i.u32filter, i.chainPrefix, err = prepareU32Rules(netif.GetIP(), i.networkConfig)
	if err != nil {
		return err
	}

	// Assemble firewall rules needed to divert traffic
	// to/from the endpoint.
	divertFilter := makeDivertRules(netif)
	log.Tracef(trace.Inside, "In SetEndpoint() after divertFilter with\n%s", divertFilter.RenderFooter())

	// compare list of divert rules and list of current rules
	// make a list of chains filled with divert rules that need
	// to be created to match current rules.
	backendFilter := i.CurrentState.TableByName("filter")
	newChains := iptsave.MergeTables(backendFilter, divertFilter)

	// schedule divert rules that don't exist yet for installation.
	newFilter := i.DesiredState.TableByName("filter")
	newFilter.Chains = append(newFilter.Chains, newChains...)

	log.Tracef(trace.Inside, "In SetEndpoint after merge\n%s", i.CurrentState.Render())

	return err
}

// EnsureRule implements Firewall interface. It schedules given rule for
// transition in given state and stores it in firewall store.
func (i *IPTsaveFirewall) EnsureRule(rule FirewallRule, opType RuleState) error {
	log.Infof("In EnsureRule() with firewall rule %s %s", opType.String(), rule.GetBody())

	var ruleExists bool

	// This firewall only manages filtering rules so it only operates
	// on `filter` table.
	table := i.DesiredState.TableByName("filter")
	if table == nil {
		return fmt.Errorf("In EnsureRule() firewall doesn't have filter table")
	}

	// Convert iptables rule from Firewall interface into iptsave.IPrule.
	tempChain := iptsave.ParseRule(bytes.NewReader([]byte(rule.GetBody())))
	ipRule := tempChain.Rules[0]

	// Ensure that base chain of the rule is defined in desired state.
	chain := table.ChainByName(tempChain.Name)
	if chain == nil {
		table.Chains = append(table.Chains, tempChain)
		chain = tempChain

		// we just added a chain with our rule
		// into the filter table so we know that
		// target rule is in the table.
		ruleExists = true
	}

	// If we didn't put that rule in the table ourselves yet then
	// try to find it in existing table.
	if !ruleExists {
		ruleExists = chain.RuleInChain(ipRule)
	}

	if ruleExists {
		switch opType {
		case EnsureAbsent:
			log.Infof("In EnsureRule - rule %s exists in current state, removing", rule.GetBody())
			chain.DeleteRule(ipRule)
		default:
			log.Infof("In EnsureRule - nothing to do %s", rule.GetBody())
		}
	} else {
		log.Infof("In EnsureRule - rule %s doesn't exist is current state, %s", rule.GetBody(), opType.String())
		switch opType {
		case EnsureLast:
			chain.AppendRule(ipRule)
		case EnsureFirst:
			chain.InsertRule(0, ipRule)
		default:
			log.Infof("In EnsureRule - nothing to do %s", rule.GetBody())
		}
	}

	return nil
}

// SetDefaultRules implements Firewall interface.
// The implementation iterates over the provided rules and ensures that each of them is present.
func (i *IPTsaveFirewall) SetDefaultRules(rules []FirewallRule) error {
	// Walking backwards to preserve original order
	for ruleNum := len(rules) - 1; ruleNum >= 0; ruleNum-- {
		if err := i.EnsureRule(rules[ruleNum], EnsureFirst); err != nil {
			return err
		}
	}

	return nil
}

// Metadata implements Firewall interface.
func (i *IPTsaveFirewall) Metadata() map[string]interface{} {
	metadata := make(map[string]interface{})
	metadata["provider"] = i.Provider()
	metadata["chainPrefix"] = i.chainPrefix
	metadata["u32filter"] = i.u32filter

	return metadata
}

// Provider implements Firewall interface.
func (i *IPTsaveFirewall) Provider() string {
	return "iptsave"
}

// ListRules implements Firewall interface.
func (i *IPTsaveFirewall) ListRules() ([]IPtablesRule, error) {
	return nil, nil
}

// Cleanup implements Firewall interface.
func (i *IPTsaveFirewall) Cleanup(netif FirewallEndpoint) error {

	// Delete netif related rules from ifirewall store and schedule
	// them for deletion from current state.
	// TODO it is possible that someone will make a chain
	// with a name that matchies interface name and this call
	// will delete all rules from such a chain.
	// This is very unlikely but still should be
	// addressed just in case. Stas.
	err := i.deleteIPtablesRulesBySubstring(netif.GetName())
	if err != nil {
		return err
	}

	// Delete netif related rules from current state.
	err = i.applyRules(i.DesiredState)
	if err != nil {
		return err
	}

	log.Tracef(trace.Inside, "In Cleanup \n%s", i.DesiredState.Render())
	return nil
}

// ProvisionEndpoint implements Firewall interface.
func (i *IPTsaveFirewall) ProvisionEndpoint() error {
	log.Tracef(trace.Public, "In ProvisionEndpoint\n%s", i.DesiredState.Render())

	// Generate a list of rules for firewall store.
	ruleList, err := makeDbRules(i.DesiredState)
	if err != nil {
		return err
	}

	// Create rules in firewall store.
	err = i.createNewDbRules(ruleList)
	if err != nil {
		return err
	}

	// Install iptables rules from desired state.
	err = i.applyRules(i.DesiredState)
	if err != nil {
		return err
	}

	// Activate rules in firewall store.
	err = i.enableNewDbRules(ruleList)
	if err != nil {
		return err
	}

	return nil
}

// createNewDbRules is a helper method that puts a list of firewall rules
// in a firewall storage.
func (i IPTsaveFirewall) createNewDbRules(ruleList []*IPtablesRule) error {

	for ruleNum, _ := range ruleList {
		rule := ruleList[ruleNum]
		log.Tracef(trace.Inside, "In createNewDbRules() storing rule %p", rule)
		err0 := i.Store.ensureIPtablesRule(rule)
		if err0 != nil {
			log.Errorf("In createNewDbRules() failed to store rule %v", rule)
			return err0
		}
	}

	return nil
}

// enableNewDbRules is a halper method that sets `enabled` flag for
// a list of firewall rules in a firewall storage.
func (i IPTsaveFirewall) enableNewDbRules(ruleList []*IPtablesRule) error {

	for ruleNum, _ := range ruleList {
		rule := ruleList[ruleNum]
		log.Tracef(trace.Inside, "In switchIPtablesRule() activating rule %p", rule)
		err0 := i.Store.switchIPtablesRule(rule, setRuleActive)
		if err0 != nil {
			log.Errorf("In enableNewDbRules() failed to enable rule %v", rule)
			return err0
		}
	}

	return nil
}

// deleteDbRules is a helper method that deletes a list of firewall rules
// from a firewall storage.
func (i IPTsaveFirewall) deleteDbRules(ruleList []*IPtablesRule) error {

	for ruleNum, _ := range ruleList {
		rule := ruleList[ruleNum]
		log.Tracef(trace.Inside, "In deleteDbRules() deleting rule %p", rule)
		err0 := i.Store.deleteIPtablesRule(rule)
		if err0 != nil {
			log.Errorf("In deleteDbRules() failed to enable rule %v", rule)
			return err0
		}
	}

	return nil
}

// deleteIPtablesRulesBySubstring deletes rules from database and generates patch for desired state
// that would bring current state ro remove same rules that were deleted from database.
func (i *IPTsaveFirewall) deleteIPtablesRulesBySubstring(substring string) error {

	rulesPtr, err := i.Store.findIPtablesRules(substring)
	if err != nil {
		return err
	}
	log.Tracef(trace.Inside, "In Cleanup - found %d rules for interface %s", len(*rulesPtr), substring)

	// This function operates on "filter" table.
	tableDesired := i.DesiredState.TableByName("filter")
	if tableDesired == nil {
		return fmt.Errorf("In Cleanup() firewall doesn't have filter table")
	}

	tableCurrent := i.CurrentState.TableByName("filter")
	if tableCurrent == nil {
		return fmt.Errorf("In Cleanup() firewall doesn't have filter table")
	}

	// walk through rules from database, check if they are present
	// in current iptables config and schedule them for deletion if necessary.
	for _, rule := range *rulesPtr {
		log.Tracef(trace.Inside, "In Cleanup - deleting rule %s", rule.GetBody())

		// ignore inactive rules, they shouldn't be
		// in current state anyway
		if rule.State == setRuleInactive.String() {
			continue
		}

		err = i.Store.deleteIPtablesRule(&rule)
		if err != nil {
			return err
		}

		makeUndoRule(&rule, tableCurrent, tableDesired)

	}

	return nil
}

// makeUndoRule checks if given rule is present in current state and if so it generates
// an undo rule in desired state.
func makeUndoRule(rule FirewallRule, tableCurrent, tableDesired *iptsave.IPtable) {
	// If rule exists in current state then we want to delete it
	// in order to do so we will generate an `undo` rule and schedule
	// the `undo` rule for installation by putting it in desired state.
	// e.g. current rule
	// "-A INPUT -j DROP"
	// `undo` rule in desired state is
	// "-D INPUT -j DROP"

	// convert iptables rule from Firewall interface into iptsave.IPrule
	tempChain := iptsave.ParseRule(bytes.NewReader([]byte(rule.GetBody())))
	ipRule := tempChain.Rules[0]

	// check if chain exists in current iptables config
	chain := tableCurrent.ChainByName(tempChain.Name)
	if chain == nil {
		// if chain isn't in iptables config then none of the rules are
		// just skip them
		return
	}

	// scheduling rule deletion
	if chain.RuleInChain(ipRule) {
		ipRule.RenderState = iptsave.RenderDeleteRule

		// check if base chain exists in DesiredState
		chain = tableDesired.ChainByName(tempChain.Name)
		if chain == nil {
			// if not then create a new one
			chain = &iptsave.IPchain{Name: tempChain.Name, Policy: "-"}
			tableDesired.Chains = append(tableDesired.Chains, chain)
		}

		chain.AppendRule(ipRule)

		// if rule targets a chain that chain must be defined
		// in an iptables table
		// It's hard to tell iptables chain from custom modules
		// in iptables rule action, like `-j RESET` could be a jump
		// to RESET chain or call to custom module with RESET name.
		// Here, strategy is to check current state for chain with
		// name that corresponds to current rule action target,
		// if such chain exist then add it in desired state as well
		// otherwise assume the call to custom module.
		// ipRule.Action.Body is the 'target' of a rule, typically the name of another chain.
		targetChain := tableCurrent.ChainByName(ipRule.Action.Body)
		if targetChain != nil {
			if inDesiredStateAlready := tableDesired.ChainByName(ipRule.Action.Body); inDesiredStateAlready == nil {
				tableDesired.Chains = append(tableDesired.Chains, targetChain)
			}
		}
	}
}

// applyRules renders desired rules and passes them as stdin to iptables-restore.
func (i *IPTsaveFirewall) applyRules(iptables *iptsave.IPtables) error {
	cmd := i.os.Cmd(iptablesRestoreBin, []string{"--noflush", "-w"})
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

// makeDivertRules creates iptables "filter" table with rules to divert traffic
// to/from given endpoint into romana chains.
func makeDivertRules(netif FirewallEndpoint) *iptsave.IPtable {
	log.Tracef(trace.Private, "In makeDivertRules() with %s", netif.GetName())
	divertTable := iptsave.IPtable{
		Name: "filter",
		Chains: []*iptsave.IPchain{
			&iptsave.IPchain{
				Name:   "INPUT",
				Policy: "-",
				Rules: []*iptsave.IPrule{
					&iptsave.IPrule{
						Action: iptsave.IPtablesAction{
							Body: ChainNameEndpointToHost,
						},
						Match: []*iptsave.Match{
							&iptsave.Match{
								Negated: false,
								Body:    "-i " + netif.GetName(),
							},
						},
					},
				},
			},
			&iptsave.IPchain{
				Name:   "OUTPUT",
				Policy: "-",
				Rules: []*iptsave.IPrule{
					&iptsave.IPrule{
						Action: iptsave.IPtablesAction{
							Body: ChainNameHostToEndpoint,
						},
						Match: []*iptsave.Match{
							&iptsave.Match{
								Negated: false,
								Body:    "-o " + netif.GetName(),
							},
						},
					},
				},
			},
			&iptsave.IPchain{
				Name:   "FORWARD",
				Policy: "-",
				Rules: []*iptsave.IPrule{
					&iptsave.IPrule{
						Action: iptsave.IPtablesAction{
							Body: ChainNameEndpointEgress,
						},
						Match: []*iptsave.Match{
							&iptsave.Match{
								Negated: false,
								Body:    "-i " + netif.GetName(),
							},
						},
					},
					&iptsave.IPrule{
						Action: iptsave.IPtablesAction{
							Body: ChainNameEndpointIngress,
						},
						Match: []*iptsave.Match{
							&iptsave.Match{
								Negated: false,
								Body:    "-o " + netif.GetName(),
							},
						},
					},
				},
			},
			&iptsave.IPchain{
				Name:   ChainNameEndpointToHost,
				Policy: "-",
			},
			/* Skipping this chain because it is similar to ChainNameEndpointIngress
			&iptsave.IPchain{
				Name: ChainNameHostToEndpoint,
				Policy: "-",
			},
			*/
			&iptsave.IPchain{
				Name:   ChainNameEndpointEgress,
				Policy: "-",
			},
			&iptsave.IPchain{
				Name:   ChainNameEndpointIngress,
				Policy: "-",
			},
		},
	}

	return &divertTable

}

// chain2rules converts rules from given chain into
// IPtablesRule form, so they can be stored in the database.
func chain2rules(chain iptsave.IPchain) []*IPtablesRule {
	var rules []*IPtablesRule

	for _, rule := range chain.Rules {
		rules = append(rules, &IPtablesRule{
			Body:  fmt.Sprintf("%s %s", chain.Name, rule),
			State: setRuleInactive.String(),
		})
	}

	return rules
}

// makeDbRules aggregates all rules from given iptables table and converts them
// into a format acceptible by firewall store.
func makeDbRules(iptables *iptsave.IPtables) ([]*IPtablesRule, error) {

	var res []*IPtablesRule

	// This function operates on "filter" table.
	table := iptables.TableByName("filter")
	if table == nil {
		return nil, fmt.Errorf("In createNewDbRules() firewall doesn't have filter table")
	}

	for _, chain := range table.Chains {
		chainRules := chain2rules(*chain)
		res = append(res, chainRules...)
	}

	return res, nil
}
