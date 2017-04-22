// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package agent

import (
	"fmt"

	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/core/pkg/util/firewall"
	log "github.com/romana/rlog"
)

// addPolicy is a placeholder. TODO
func (a *Agent) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	//	policy := input.(*common.Policy)
	return nil, nil
}

// deletePolicy is a placeholder. TODO
func (a *Agent) deletePolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	//	policyId := ctx.PathVariables["policyID"]
	return nil, nil
}

// listPolicies is a placeholder. TODO.
func (a *Agent) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
	return nil, nil
}

// Status is a structure containing statistics returned by statusHandler
type Status struct {
	Rules      []firewall.IPtablesRule `json:"rules"`
	Interfaces []NetIf                 `json:"interfaces"`
}

// statusHandler reports operational statistics.
func (a *Agent) statusHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Trace(trace.Private, "Agent: Entering statusHandler()")

	fw, err := firewall.NewFirewall(a.getFirewallType())
	if err != nil {
		return nil, err
	}

	err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
	if err != nil {
		return nil, err
	}

	rules, err := fw.ListRules()
	if err != nil {
		return nil, err
	}
	ifaces, err := a.store.listNetIfs()
	if err != nil {
		return nil, err
	}
	status := Status{Rules: rules, Interfaces: ifaces}
	return status, nil
}

// podDownHandler cleans up after pod deleted.
func (a *Agent) podDownHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Trace(trace.Private, "Agent: Entering podDownHandler()")
	netReq := input.(*NetworkRequest)
	netif := netReq.NetIf

	if a.policyEnabled {
		// We need new firewall instance here to use its Cleanup()
		// to uninstall firewall rules related to the endpoint.
		fw, err := firewall.NewFirewall(a.getFirewallType())
		if err != nil {
			return nil, err
		}

		err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
		if err != nil {
			return nil, err
		}

		err = fw.Cleanup(netif)
		if err != nil {
			return nil, err
		}
	}

	// Spawn new thread to process the request
	log.Infof("Agent: Got request for pod teardown %v\n", netReq)

	return "OK", nil
}

// podUpHandler handles HTTP requests for endpoints provisioning.
func (a *Agent) podUpHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Trace(trace.Private, "Agent: Entering podUpHandler()")
	netReq := input.(*NetworkRequest)

	log.Infof("Agent: Got request for network configuration: %v\n", netReq)
	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.podUpHandlerAsync(*netReq)

	// TODO I wonder if this should actually return something like a
	// link to a status of this request which will later get updated
	// with success or failure -- Greg.
	return "OK", nil
}

// vmDownHandler handles HTTP requests for endpoints teardown.
func (a *Agent) vmDownHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Tracef(trace.Private, "In vmDownHandler() with %T %v", input, input)
	netif := input.(*NetIf)
	if netif.Name == "" {
		// This is a request from OpenStack Mech driver who does not have a name,
		// let's find it by mac.
		err := a.store.findNetIf(netif)
		if err != nil {
			return nil, err
		}
	}
	log.Infof("Agent: Provisioning DHCP for %s, IP %s Mac %s\n", netif.Name, netif.IP, netif.Mac)

	if err := a.leaseFile.provisionLease(netif, leaseRemove); err != nil {
		log.Error(agentError(err))
		return "Error removing DHCP lease", agentError(err)
	}

	if a.policyEnabled {
		// We need new firewall instance here to use it's Cleanup()
		// to uninstall firewall rules related to the endpoint.
		fw, err := firewall.NewFirewall(a.getFirewallType())
		if err != nil {
			return nil, err
		}

		err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
		if err != nil {
			return nil, err
		}

		err = fw.Cleanup(netif)
		if err != nil {
			return nil, err
		}
		err = a.store.deleteNetIf(netif)
		if err != nil {
			return nil, err
		}
	}
	return "OK", nil
}

// vmUpHandler handles HTTP requests for endpoints provisioning.
// Currently tested with Romana ML2 driver.
func (a *Agent) vmUpHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	// Parse out NetIf form the request
	netif := input.(*NetIf)

	log.Infof("Agent: Got interface: Name %s, IP %s Mac %s\n", netif.Name, netif.IP, netif.Mac)

	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.vmUpHandlerAsync(*netif)

	// TODO I wonder if this should actually return something like a
	// link to a status of this request which will later get updated
	// with success or failure -- Greg.
	return "OK", nil
}

// podUpHandlerAsync does a number of operations on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Creates ip route pointing new interface
// 3. Provisions firewall rules
func (a *Agent) podUpHandlerAsync(netReq NetworkRequest) error {
	log.Trace(trace.Private, "Agent: Entering podUpHandlerAsync()")
	currentProvider := a.getFirewallType()

	netif := netReq.NetIf
	if netif.Name == "" {
		return agentErrorString("Agent: Interface name required")
	}
	if !a.Helper.waitForIface(netif.Name) {
		// TODO should we resubmit failed interface in queue for later
		// retry ? ... considering openstack will give up as well after
		// timeout
		msg := fmt.Sprintf("Requested interface not available in time - %s", netif.Name)
		log.Warn("Agent: ", msg)
		return agentErrorString(msg)
	}
	log.Infof("Agent: Creating endpoint routes - %s", netif.Name)
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		log.Error(agentError(err))
		return agentError(err)
	}

	if a.policyEnabled {
		log.Infof("Agent: Provisioning firewall - %s", netif.Name)
		fw, err := firewall.NewFirewall(currentProvider)
		if err != nil {
			return err
		}

		err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
		if err != nil {
			return err
		}

		if err1 := fw.SetEndpoint(netif); err1 != nil {
			log.Error(agentError(err))
			return agentError(err)
		}

		var rules RuleSet
		switch currentProvider {
		case firewall.ShellexProvider:
			rules = KubeShellXRules
		case firewall.IPTsaveProvider:
			rules = KubeSaveRestoreRules
		default:
			err := fmt.Errorf("Unkown firewall provider in podUpHandler")
			log.Error(agentError(err))
			return agentError(err)
		}

		if err := prepareFirewallRules(fw, a.networkConfig, rules, currentProvider); err != nil {
			log.Error(agentError(err))
			return agentError(err)
		}

		if err := fw.ProvisionEndpoint(); err != nil {
			log.Error(agentError(err))
			return agentError(err)
		}

		if ip, err := IpToNet(netif.IP.IP); err == nil {
			a.routec <- ip
		}
	}

	log.Trace(trace.Inside, "Agent: All good", netif)
	return nil
}

func prepareFirewallRules(fw firewall.Firewall, nc *NetworkConfig, rules RuleSet, firewallProvider firewall.Provider) error {
	metadata := fw.Metadata()

	var defaultRules []firewall.FirewallRule
	var u32filter string = metadata["u32filter"].(string)
	var hostAddr = nc.RomanaGW()
	var formatBody string

	switch firewallProvider {
	case firewall.ShellexProvider:
		var chainNames []string = metadata["chains"].([]string)

		for _, rule := range rules {
			log.Tracef(trace.Inside, "In prepareFirewallRules(), with %v", rule)

			var currentChain string
			switch rule.Direction {
			case EgressLocalDirection:
				currentChain = chainNames[firewall.InputChainIndex]
			case EgressGlobalDirection:
				currentChain = chainNames[firewall.ForwardOutChainIndex]
			case IngressGlobalDirection:
				currentChain = chainNames[firewall.ForwardInChainIndex]
			default:
				return fmt.Errorf("Error, unsupported rule direction type with firewall provider %d", firewallProvider)
			}

			switch rule.Format {
			case FormatChain:
				formatBody = fmt.Sprintf(rule.Body, currentChain)
			case FormatChainHostU32TenantSegment:
				formatBody = fmt.Sprintf(rule.Body, currentChain, hostAddr, u32filter)
			default:
				return fmt.Errorf("Error, unsupported rule format type with firewall provider %d", firewallProvider)
			}

			r := firewall.NewFirewallRule()
			r.SetBody(formatBody)

			switch rule.Position {
			case DefaultPosition:
				defaultRules = append(defaultRules, r)
			default:
				return fmt.Errorf("Error, unsupported rule position with firewall provider %d", firewallProvider)
			}
		}
	case firewall.IPTsaveProvider:
		for _, rule := range rules {
			log.Tracef(trace.Inside, "In prepareFirewallRules(), with %v", rule)

			var currentChain string
			switch rule.Direction {
			case EgressLocalDirection:
				currentChain = firewall.ChainNameEndpointToHost
			case EgressGlobalDirection:
				currentChain = firewall.ChainNameEndpointEgress
			case IngressGlobalDirection:
				currentChain = firewall.ChainNameEndpointIngress
			default:
				return fmt.Errorf("Error, unsupported rule direction type with firewall provider %d", firewallProvider)
			}

			switch rule.Format {
			case FormatChain:
				formatBody = fmt.Sprintf(rule.Body, currentChain)
			case FormatChainHostU32TenantSegment:
				formatBody = fmt.Sprintf(rule.Body, currentChain, hostAddr, u32filter)
			default:
				return fmt.Errorf("Error, unsupported rule format type with firewall provider %d", firewallProvider)
			}

			r := firewall.NewFirewallRule()
			r.SetBody(formatBody)

			switch rule.Position {
			case TopPosition:
				fw.EnsureRule(r, firewall.EnsureFirst)
			case BottomPosition:
				fw.EnsureRule(r, firewall.EnsureLast)
			default:
				return fmt.Errorf("Error, unsupported rule position with firewall provider %d", firewallProvider)
			}
		}
	default:
		return fmt.Errorf("Error, unsupported firewall provider type when preparing firewall rules")
	}

	return nil
}

// vmUpHandlerAsync does a number of operations on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Checks if DHCP is running
// 3. Creates ip route pointing new interface
// 4. Provisions static DHCP lease for new interface
// 5. Provisions firewall rules
func (a *Agent) vmUpHandlerAsync(netif NetIf) error {
	log.Trace(trace.Private, "Agent: Entering interfaceHandle()")
	currentProvider := a.getFirewallType()

	if !a.Helper.waitForIface(netif.Name) {
		// TODO should we resubmit failed interface in queue for later
		// retry ? ... considering oenstack will give up as well after
		// timeout
		return agentErrorString(fmt.Sprintf("Requested interface not available in time - %s", netif.Name))
	}

	// dhcpPid is only needed here for fail fast check
	// will try to poll the pid again in provisionLease
	log.Trace(trace.Inside, "Agent: Checking if DHCP is running")
	_, err := a.Helper.DhcpPid()
	if err != nil {
		log.Error(agentError(err))
		return agentError(err)
	}
	err = a.store.addNetIf(&netif)
	if err != nil {
		return agentError(err)
	}
	log.Infof("Agent: Creating endpoint routes - %s", netif.Name)
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		log.Error(agentError(err))
		return agentError(err)
	}
	log.Infof("Agent: Provisioning DHCP - %s", netif.Name)
	if err := a.leaseFile.provisionLease(&netif, leaseAdd); err != nil {
		log.Error(agentError(err))
		return agentError(err)
	}

	if a.policyEnabled {
		log.Infof("Agent: Provisioning firewall - %s", netif.Name)
		fw, err := firewall.NewFirewall(currentProvider)
		if err != nil {
			return err
		}

		err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
		if err != nil {
			log.Error(agentError(err))
			return agentError(err)
		}

		if err1 := fw.SetEndpoint(netif); err1 != nil {
			log.Error(agentError(err1))
			return agentError(err1)
		}

		var rules RuleSet
		switch currentProvider {
		case firewall.ShellexProvider:
			rules = OpenStackShellRules
		case firewall.IPTsaveProvider:
			rules = OpenStackSaveRestoreRules
		default:
			err := fmt.Errorf("Unkown firewall provider in vmUpHandler")
			log.Error(agentError(err))
			return agentError(err)
		}

		if err := prepareFirewallRules(fw, a.networkConfig, rules, currentProvider); err != nil {
			log.Error(agentError(err))
			return agentError(err)
		}

		if err := fw.ProvisionEndpoint(); err != nil {
			log.Error(agentError(err))
			return agentError(err)
		}

		if ip, err := IpToNet(netif.IP.IP); err == nil {
			a.routec <- ip
		}
	}

	log.Trace(trace.Inside, "All good", netif)
	return nil
}

// getFirewallType converts configuration option firewall_provider into
// firewall.Provider type.
func (a Agent) getFirewallType() firewall.Provider {
	provider, ok := a.config.ServiceSpecific["firewall_provider"].(string)
	if !ok {
		panic("Unable to read firewall_provider from config")
	}

	// Value of "shellex" stands for firewall provider that executes iptables
	// commands line by line and value of "save-restore" stands for
	// firewall provider that uses iptables-save/iptables-restore.
	switch provider {
	case "shellex":
		log.Trace(trace.Inside, "Agent: using ShellexProvider firewall provider")
		return firewall.ShellexProvider
	case "save-restore":
		log.Trace(trace.Inside, "Agent: using IPTsaveProvider firewall provider")
		return firewall.IPTsaveProvider
	default:
		panic(fmt.Sprintf("Unsupported firewall type value %s, supported values are 'shellex' and 'save-restore'", provider))
	}

}
