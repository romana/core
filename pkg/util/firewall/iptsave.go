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
	"github.com/golang/glog"
	utilexec "github.com/romana/core/pkg/util/exec"
	"github.com/romana/core/pkg/util/iptsave"
)

const (
	//	InputChainIndex      = 0
	//	OutputChainIndex     = 1
	//	ForwardInChainIndex  = 2
	//	ForwardOutChainIndex = 3

	iptablesSaveBin    = `/sbin/iptables-save`
	iptablesRestoreBin = `/sbin/iptables-restore`
)

// IPtables implements romana Firewall using iptables.
type IPTsaveFirewall struct {
	//	chains        []IPtablesChain
	u32filter     string
	chainPrefix   string
	interfaceName string

	CurrentRules *iptsave.IPtables
	NewRules     *iptsave.IPtables
	Store        firewallStore
	newRules     []IPtablesRule

	os          utilexec.Executable
	initialized bool

	// Discovered run-time configuration.
	networkConfig NetConfig
}

// Init implements Firewall interface
func (i *IPTsaveFirewall) Init(exec utilexec.Executable, store FirewallStore, nc NetConfig) error {
	glog.V(1).Infof("In Init()")

	fwstore := firewallStore{}
	fwstore.DbStore = store.GetDb()
	fwstore.mu = store.GetMutex()

	i.Store = fwstore
	i.os = exec
	i.networkConfig = nc

	// Read current iptables config
	output, err := i.os.Exec(iptablesSaveBin, []string{})
	if err != nil {
		glog.V(1).Infof("In Init(), failed to call iptables-save, %s", err)
		return err
	}

	// Parse iptables-save output
	i.CurrentRules = &iptsave.IPtables{}
	i.CurrentRules.Parse(bytes.NewReader(output))

	
	i.NewRules = &iptsave.IPtables{}
	i.NewRules.Tables = append(i.NewRules.Tables, &iptsave.IPtable{Name: "filter"})
	glog.V(4).Infof("In Init(), iptables rules loaded\n, %s", i.CurrentRules.Render())

	return nil
}

func (i *IPTsaveFirewall) SetEndpoint(netif FirewallEndpoint) error {
	var err error
	i.interfaceName = netif.GetName()

	i.u32filter, i.chainPrefix, err = prepareU32Rules(netif.GetIP(), i.networkConfig)
	if err != nil {
		// TODO need personalized error here, or even panic
		return err
	}

	// Assemble firewall rules needed to divert traffic
	// to/from the endpoint
	divertFilter := makeDivertRules(netif)
	glog.V(3).Infof("In SetEndpoint() after divertFilter with\n%s", divertFilter.RenderFooter())

	// compare list of divert rules and list of current rules
	backendFilter := i.CurrentRules.TableByName("filter")
	newChains := iptsave.MergeTables(backendFilter, divertFilter)

	// schedule divert rules that aren't exist yet for installation
	newFilter := i.NewRules.TableByName("filter")
	newFilter.Chains = append(newFilter.Chains, newChains...)

	glog.V(4).Infof("In SetEndpoint after merge\n%s", i.CurrentRules.Render())

	i.initialized = true
	return err
}

// chain2rules converts rules from given chain into
// IPtablesRule form so the could be stored in database
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

// makeDivertRules creates iptables "filter" table with rules for the given endpoint.
func makeDivertRules(netif FirewallEndpoint) *iptsave.IPtable {
	glog.V(3).Infof("In makeDivertRules() with %s", netif.GetName())
	divertTable := iptsave.IPtable{
		Name: "filter",
		Chains: []*iptsave.IPchain{
			&iptsave.IPchain{
				Name: "INPUT",
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
				Name: "OUTPUT",
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
				Name: "FORWARD",
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
				Name: ChainNameEndpointToHost,
				Policy: "-",
			},
			/* Skipping this chain because it is similar to ChainNameEndpointIngress
				&iptsave.IPchain{
					Name: ChainNameHostToEndpoint,
					Policy: "-",
				},
			*/
			&iptsave.IPchain{
				Name: ChainNameEndpointEgress,
				Policy: "-",
			},
			&iptsave.IPchain{
				Name: ChainNameEndpointIngress,
				Policy: "-",
			},
		},
	}

	return &divertTable

}

// SetDefaultRules implements Firewall interface.
func (i *IPTsaveFirewall) SetDefaultRules(rules []FirewallRule) error {
	// Walking backwards to preserve original order
	length := len(rules)
	for ruleNum, _ := range rules {
		if err := i.EnsureRule(rules[length - ruleNum -1], ensureFirst); err != nil {
			return err
		}
	}
	return nil
}

func (i *IPTsaveFirewall) ProvisionEndpoint() error {
	glog.V(4).Infof("In ProvisionEndpoint\n%s", i.NewRules.Render())

	ruleList, err := i.listNewRules()
	if err != nil { 
		return err
	}

	err = i.createNewDbRules(ruleList)
	if err != nil {
		return err
	}

	err = i.applyRules(i.NewRules)
	if err != nil {
		return err
	}

	// TODO iptables-restore < i.NewRules.Render()

	err = i.enableNewDbRules(ruleList)
	if err != nil {
		return err
	}

	return nil
}

// listNewRules returns combined list of rules from 
// NewRules in IPtablesRule format.
func (i *IPTsaveFirewall) listNewRules() ([]*IPtablesRule, error) {

	var res []*IPtablesRule

	// This function operates on "filter" table.
	table := i.NewRules.TableByName("filter")
	if table == nil {
		return nil, fmt.Errorf("In createNewDbRules() firewall doesn't have filter table")
	}

	for _, chain := range table.Chains {
		chainRules := chain2rules(*chain)
		res = append(res, chainRules...)
	}

	return res, nil
}
	

func (i IPTsaveFirewall) createNewDbRules(ruleList []*IPtablesRule) error {

	for ruleNum, _ := range ruleList {
		rule := ruleList[ruleNum]
		glog.V(3).Infof("In createNewDbRules() storing rule %p", rule)
//		err0 := i.Store.addIPtablesRule(rule)
		err0 := i.Store.ensureIPtablesRule(rule)
		if err0 != nil {
			glog.Errorf("In createNewDbRules() failed to store rule %s", rule)
			return err0
		}
	}

	return nil
}

func (i IPTsaveFirewall) enableNewDbRules(ruleList []*IPtablesRule) error {

	for ruleNum, _ := range ruleList {
		rule := ruleList[ruleNum]
		glog.V(3).Infof("In switchIPtablesRule() activating rule %p", rule)
		err0 := i.Store.switchIPtablesRule(rule, setRuleActive)
		if err0 != nil {
			glog.Errorf("In enableNewDbRules() failed to enable rule %s", rule)
			return err0
		}
	}

	return nil
}

func (i IPTsaveFirewall) deleteNewDbRules(ruleList []*IPtablesRule) error {

	for ruleNum, _ := range ruleList {
		rule := ruleList[ruleNum]
		glog.V(3).Infof("In deleteNewDbRules() deleting rule %p", rule)
		err0 := i.Store.deleteIPtablesRule(rule)
		if err0 != nil {
			glog.Errorf("In deleteNewDbRules() failed to enable rule %s", rule)
			return err0
		}
	}

	return nil
}

// EnsureRule implements Firewall interface.
func (i *IPTsaveFirewall) EnsureRule(rule FirewallRule, opType RuleState) error {
	var ruleExists bool

	// This function operates on "filter" table.
	table := i.NewRules.TableByName("filter")
	if table == nil {
		return fmt.Errorf("In EnsureRule() firewall doesn't have filter table")
	}

	// convert iptables rule from Firewall interface into iptsave.IPrule
	tempChain := iptsave.ParseRule(bytes.NewReader([]byte(rule.GetBody())))
	ipRule := tempChain.Rules[0]

	// ensure that target chain exists in the table
	chain := table.ChainByName(tempChain.Name)
	if chain == nil {
		table.Chains = append(table.Chains, tempChain)
		chain = tempChain
		ruleExists = true
		
	} else {
		ruleExists = chain.RuleInChain(ipRule)
	}


	if ruleExists && opType == ensureAbsent {
		glog.Infof("In EnsureRule - rule %s exists in current state, removing", rule.GetBody())
		chain.DeleteRule(ipRule)
	} else if !ruleExists {
		glog.Infof("In EnsureRule - rule %s doesn't exist is current state, %s", rule.GetBody(), opType.String())
		switch opType {
		case ensureLast:
			chain.AppendRule(ipRule)
		case ensureFirst:
			chain.InsertRule(0, ipRule)
		}
	} else {
		glog.Infof("In EnsureRule - nothing to do %s", rule.GetBody())
		return nil
	}
	
	return nil
}



func (i *IPTsaveFirewall) Metadata() map[string]interface{} {
	metadata := make(map[string]interface{})
	metadata["provider"] = i.Provider()
	metadata["chainPrefix"] = i.chainPrefix
	metadata["u32filter"] = i.u32filter

	return metadata
}

func (i *IPTsaveFirewall) Provider() string {
	return "iptsave"
}

func (i *IPTsaveFirewall) ListRules() ([]IPtablesRule, error) {
	return nil, nil
}

func (i *IPTsaveFirewall) Cleanup(netif FirewallEndpoint) error {
	err := i.deleteIPtablesRulesBySubstring(netif.GetName())
	if err != nil {
		return err
	}

	err = i.applyRules(i.NewRules)
	if err != nil {
		return err
	}
	
	glog.V(4).Infof("In Cleanup \n%s", i.NewRules.Render())
	return nil
}


func (i *IPTsaveFirewall) deleteIPtablesRulesBySubstring(substring string) error {
	rules, err := i.Store.findIPtablesRules(substring)
	if err != nil {
		return err
	}
	glog.V(2).Infof("In Cleanup - found %d rules for interface %s", len(*rules), substring)

	// This function operates on "filter" table.
	tableNew := i.NewRules.TableByName("filter")
	if tableNew == nil {
		return fmt.Errorf("In Cleanup() firewall doesn't have filter table")
	}

	tableCurrent := i.CurrentRules.TableByName("filter")
	if tableCurrent == nil {
		return fmt.Errorf("In Cleanup() firewall doesn't have filter table")
	}


	// walk through rules from database, check if they are present
	// in current iptables config and schedule them for deletion if necessary.
	for _, rule := range *rules {
		glog.V(3).Infof("In Cleanup - deleting rule %s", rule.GetBody())

		// ignore inactive rules, they shouldn't be
		// in current state anyway
		if rule.State == setRuleInactive.String() {
			continue
		}

		err = i.Store.deleteIPtablesRule(&rule)
		if err != nil {
			return err
		}

		// convert iptables rule from Firewall interface into iptsave.IPrule
		tempChain := iptsave.ParseRule(bytes.NewReader([]byte(rule.GetBody())))
		ipRule := tempChain.Rules[0]

		// check if chain exists in current iptables config
		chain := tableCurrent.ChainByName(tempChain.Name)
		if chain == nil {
			// if chain isn't in iptables config then non of the rules are
			// just skip them
			continue
		}

		// scheduling rule deletion
		if chain.RuleInChain(ipRule) {
			ipRule.RenderState = iptsave.RenderDeleteRule

			// check if base chain exists in DesiredState
			chain = tableNew.ChainByName(tempChain.Name)
			if chain == nil {
				// if not then create a new one
				chain = &iptsave.IPchain{Name: tempChain.Name, Policy: "-"}
				tableNew.Chains = append(tableNew.Chains, chain)
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
			targetChain := tableCurrent.ChainByName(ipRule.Action.Body)
			if targetChain != nil {
				tableNew.Chains = append(tableNew.Chains, &iptsave.IPchain{Name: ipRule.Action.Body, Policy: "-"})
			}
		}
	}

	return nil
}

func (i *IPTsaveFirewall) applyRules(iptables *iptsave.IPtables) error {
	cmd := i.os.Cmd(iptablesRestoreBin, []string{"--noflush"})
	reader := bytes.NewReader([]byte(iptables.Render()))

	glog.V(3).Infof("In applyRules allocating stdin pipe")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		panic(fmt.Sprintf("Failed to allocate stdin for iptables-restore - %s", err))
	}

	glog.V(3).Infof("In applyRules starting the command")
	if err := cmd.Start(); err != nil {
		return err
	}

	glog.V(3).Infof("In applyRules sending the rules")
	_, err = reader.WriteTo(stdin)
	if err != nil {
		return err
	}

	stdin.Close()

	glog.V(3).Infof("In applyRules waiting for command to complete")
	if err := cmd.Wait(); err != nil {
		glog.V(3).Infof("In applyRules failed to apply")
		return err
	}

	return nil
}
