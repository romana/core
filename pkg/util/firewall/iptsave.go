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
	"github.com/romana/core/pkg/util/iptsave"
	utilexec "github.com/romana/core/pkg/util/exec"
	"bytes"
	"github.com/golang/glog"
	"fmt"
	"strings"
)


const (
//	InputChainIndex      = 0
//	OutputChainIndex     = 1
//	ForwardInChainIndex  = 2
//	ForwardOutChainIndex = 3

	iptablesSaveBin = `/sbin/iptables-save`
	iptablesRestoreBin = `/sbin/iptables-restore`

)

// IPtables implements romana Firewall using iptables.
type IPTsaveFirewall struct {
//	chains        []IPtablesChain
	u32filter     string
	chainPrefix   string
	interfaceName string

	Backend *iptsave.IPtables
	Store         firewallStore

	os            utilexec.Executable
	initialized   bool

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
	output, err := i.os.Exec(iptablesSaveBin,[]string{})
	if err != nil {
		glog.V(1).Infof("In Init(), failed to call iptables-save, %s", err)
		return err
	}

	// Parse iptables-save output
	i.Backend = &iptsave.IPtables{}
	i.Backend.Parse(bytes.NewReader(output))
	glog.V(4).Infof("In Init(), iptables rules loaded\n, %s", i.Backend.Render())

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

	backendFilter := i.Backend.TableByName("filter")
	divertFilter := makeDivertRules(netif)
	iptsave.MergeTables(backendFilter, divertFilter)

	glog.V(4).Infof("In SetEndpoint after merge\n%s", i.Backend.Render())

	i.initialized = true
	return err
}

// makeDivertRules creates iptables "filter" table with rules for the given endpoint.
func makeDivertRules(netif FirewallEndpoint) *iptsave.IPtable {
	divertTable := iptsave.IPtable{
		Name: "filter",
		Chains: []*iptsave.IPchain{
			&iptsave.IPchain{
				Name: "INPUT",
				Rules: []*iptsave.IPrule{
					&iptsave.IPrule{
						Action: iptsave.IPtablesAction{
							Body: ChainNameEndpointToHost,
						},
						Match: []*iptsave.Match{
							&iptsave.Match{
								Negated: false,
								Body: "-i " + netif.GetName(),
							},
						},
					},
				},
			},
			&iptsave.IPchain{
				Name: "OUTPUT",
				Rules: []*iptsave.IPrule{
					&iptsave.IPrule{
						Action: iptsave.IPtablesAction{
							Body: ChainNameHostToEndpoint,
						},
						Match: []*iptsave.Match{
							&iptsave.Match{
								Negated: false,
								Body: "-o " + netif.GetName(),
							},
						},
					},
				},
			},
			&iptsave.IPchain{
				Name: "FORWARD",
				Rules: []*iptsave.IPrule{
					&iptsave.IPrule{
						Action: iptsave.IPtablesAction{
							Body: ChainNameEndpointEgress,
						},
						Match: []*iptsave.Match{
							&iptsave.Match{
								Negated: false,
								Body: "-i " + netif.GetName(),
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
								Body: "-o " + netif.GetName(),
							},
						},
					},
				},
			},
			&iptsave.IPchain{
				Name: ChainNameEndpointToHost,
			},
			/* Skipping this chain because it is similar to ChainNameEndpointIngress
				&iptsave.IPchain{
					Name: ChainNameHostToEndpoint,
				},
			*/
			&iptsave.IPchain{
				Name: ChainNameEndpointEgress,
			},
			&iptsave.IPchain{
				Name: ChainNameEndpointIngress,
			},
		},
	}

	return &divertTable

}

// SetDefaultRules implements Firewall interface.
func (i *IPTsaveFirewall) SetDefaultRules(rules []FirewallRule) error {
	for _, rule := range rules {
		glog.V(1).Infof("In SetDefaultRules() processing rule %s", rule.GetBody())
		if rule.GetType() == "iptables" {
			iptablesRule := &IPtablesRule{
				Body:  rule.GetBody(),
				State: setRuleInactive.String(),
			}

			err := i.injectRule(iptablesRule)
			if err != nil {
				return fmt.Errorf("In SetDefaultRules() failed to set the rule %s, %s", rule.GetBody(), err)
			}

		} else {
			return fmt.Errorf("In SetDefaultRules() unsupported rule type %s", rule.GetType())
		}
	}

	return nil
}

// injectRule puts provided rule into appropriate chain into "filter" table.
func (i *IPTsaveFirewall) injectRule(rule *IPtablesRule) error {
	rule2arr := strings.Split(rule.Body, " ")
	if len(rule2arr) < 3 {
		return fmt.Errorf("In injectRule() too many elements in rule %s", rule.Body)
	}

	var action string
	var match string
	ruleChain := rule2arr[0]
	for tn, t := range rule2arr {
		if t == "-j" {
			action = strings.Join(rule2arr[tn+1:], " ")
			match = strings.Join(rule2arr[1:tn], " ")
			match += " " // TODO fix to account for iptsave lexer catching extra space
			break
		}
	}

	table := i.Backend.TableByName("filter")
	if table == nil {
		fmt.Errorf("In injectRule() firewall doesn't have firewall table\n")
	}

	chain := table.ChainByName("ruleChain")
	if chain == nil {
		chain = &iptsave.IPchain{
				Name: ruleChain,
				Policy: "-",
		}

		table.Chains = append(table.Chains, chain)	
	}

	IPrule := &iptsave.IPrule{
		Action: iptsave.IPtablesAction{
			Body: action,
		},
		Match: []*iptsave.Match{
			&iptsave.Match{
				Negated: false,
				Body: match,
			},
		},
	}

	if !chain.RuleInChain(IPrule) {
		glog.V(2).Infof("In SetDefaultRules inserting rule %s", IPrule.String())
		chain.InsertRule(1, IPrule)
	}

	return nil
}

func (i *IPTsaveFirewall) ProvisionEndpoint() error {
	glog.V(4).Infof("In ProvisionEndpoint\n%s", i.Backend.Render())
	return nil
}

func (i *IPTsaveFirewall) EnsureRule(*IPtablesRule, RuleState) error {
	return nil
}

func (i *IPTsaveFirewall) Metadata() map[string]interface{} {
	return nil
}

func (i *IPTsaveFirewall) Provider() string { 
	return "iptsave"
}

func (i *IPTsaveFirewall) ListRules() ([]IPtablesRule, error) {
	return nil, nil
}

func (i *IPTsaveFirewall) Cleanup(netif FirewallEndpoint) error {
	return nil
}
