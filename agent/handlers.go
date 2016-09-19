package agent

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/romana/core/common"
	"github.com/romana/core/pkg/util/firewall"
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
	glog.V(1).Infoln("Agent: Entering statusHandler()")
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
	glog.V(1).Infoln("Agent: Entering podDownHandler()")
	netReq := input.(*NetworkRequest)
	netif := netReq.NetIf

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

	// Spawn new thread to process the request
	glog.Infof("Agent: Got request for pod teardown %v\n", netReq)

	return "OK", nil
}

// podUpHandler handles HTTP requests for endpoints provisioning.
func (a *Agent) podUpHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	glog.Infof("Agent: Entering podUpHandler()")
	netReq := input.(*NetworkRequest)

	glog.Infof("Agent: Got request for network configuration: %v\n", netReq)
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
	glog.Infof("In vmDownHandler() with %T %v", input, input)
	netif := input.(*NetIf)
	if netif.Name == "" {
		// This is a request from OpenStack Mech driver who does not have a name, let's find it.
		err := a.store.findNetIf(netif)
		if err != nil {
			return nil, err
		}
	}
	glog.Infof("In vmDownHandler() with Name %s, IP %s Mac %s\n", netif.Name, netif.IP, netif.Mac)

	glog.Info("Agent: provisioning DHCP")
	if err := a.leaseFile.provisionLease(netif, leaseRemove); err != nil {
		glog.Error(agentError(err))
		return "Error removing DHCP lease", agentError(err)
	}

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
	return "OK", nil
}

// vmUpHandler handles HTTP requests for endpoints provisioning.
// Currently tested with Romana ML2 driver.
func (a *Agent) vmUpHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	// Parse out NetIf form the request
	netif := input.(*NetIf)

	glog.Infof("Got interface: Name %s, IP %s Mac %s\n", netif.Name, netif.IP, netif.Mac)

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
	glog.V(1).Info("Agent: Entering podUpHandlerAsync()")
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
		glog.Infoln("Agent: ", msg)
		return agentErrorString(msg)
	}
	glog.Info("Agent: creating endpoint routes")
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	glog.Info("Agent: provisioning firewall")
	fw, err := firewall.NewFirewall(currentProvider)
	if err != nil {
		return err
	}

	err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
	if err != nil {
		return err
	}

	if err1 := fw.SetEndpoint(netif); err1 != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	var rules RuleSet
	switch currentProvider {
	case firewall.ShellexProvider:
		rules = KubeShellRules
	case firewall.IPTsaveProvider:
		rules = KubeSaveRestoreRules
	default:
		err := fmt.Errorf("Unkown firewall provider in podUpHandler")
		glog.Error(agentError(err))
		return agentError(err)
	}

	if err := prepareFirewallRules(fw, a.networkConfig, rules, currentProvider); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	if err := fw.ProvisionEndpoint(); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	glog.Info("Agent: All good", netif)
	return nil
}

func prepareFirewallRules(fw firewall.Firewall, nc *NetworkConfig, rules RuleSet, firewallProvider firewall.Provider) error {
	metadata := fw.Metadata()

	var defaultRules []firewall.FirewallRule
	var u32filter string = metadata["u32filter"].(string)
	var chainNames []string = metadata["chains"].([]string)
	var hostAddr = nc.RomanaGW()
	var formatBody string

	switch firewallProvider {
	case firewall.ShellexProvider:
		for _, rule := range rules {
			glog.V(2).Infof("In prepareFirewallRules(), with %v", rule)

			var currentChain string
			switch rule.Direction {
			case EgressLocalDirection:
				currentChain = chainNames[firewall.InputChainIndex]
			case EgressGlobalDirection:
				currentChain = chainNames[firewall.ForwardOutChainIndex]
			case IngressGlobalDirection:
				currentChain = chainNames[firewall.ForwardInChainIndex]
			default:
				return fmt.Errorf("Error, unsupported rule direction type with firewall provider %s", firewallProvider)
			}

			switch rule.Format {
			case FormatChain:
				formatBody = fmt.Sprintf(rule.Body, currentChain)
			case FormatChainHostU32TenantSegment:
				formatBody = fmt.Sprintf(rule.Body, currentChain, hostAddr, u32filter)
			default:
				return fmt.Errorf("Error, unsupported rule format type with firewall provider %s", firewallProvider)
			}

			r := firewall.NewFirewallRule()
			r.SetBody(formatBody)

			switch rule.Position {
			case DefaultPosition:
				defaultRules = append(defaultRules, r)
			default:
				return fmt.Errorf("Error, unsupported rule position with firewall provider %s", firewallProvider)
			}
		}
	case firewall.IPTsaveProvider:
		for _, rule := range rules {
			glog.V(2).Infof("In prepareFirewallRules(), with %v", rule)

			var currentChain string
			switch rule.Direction {
			case EgressLocalDirection:
				currentChain = firewall.ChainNameEndpointToHost
			case EgressGlobalDirection:
				currentChain = firewall.ChainNameEndpointEgress
			case IngressGlobalDirection:
				currentChain = firewall.ChainNameEndpointIngress
			default:
				return fmt.Errorf("Error, unsupported rule direction type with firewall provider %s", firewallProvider)
			}

			switch rule.Format {
			case FormatChain:
				formatBody = fmt.Sprintf(rule.Body, currentChain)
			case FormatChainHostU32TenantSegment:
				formatBody = fmt.Sprintf(rule.Body, currentChain, hostAddr, u32filter)
			default:
				return fmt.Errorf("Error, unsupported rule format type with firewall provider %s", firewallProvider)
			}

			r := firewall.NewFirewallRule()
			r.SetBody(formatBody)

			switch rule.Position {
			case TopPosition:
				fw.EnsureRule(r, firewall.EnsureFirst)
			case BottomPosition:
				fw.EnsureRule(r, firewall.EnsureLast)
			default:
				return fmt.Errorf("Error, unsupported rule position with firewall provider %s", firewallProvider)
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
	glog.V(1).Info("Agent: Entering interfaceHandle()")
	currentProvider := a.getFirewallType()

	if !a.Helper.waitForIface(netif.Name) {
		// TODO should we resubmit failed interface in queue for later
		// retry ? ... considering oenstack will give up as well after
		// timeout
		return agentErrorString(fmt.Sprintf("Requested interface not available in time - %s", netif.Name))
	}

	// dhcpPid is only needed here for fail fast check
	// will try to poll the pid again in provisionLease
	glog.Info("Agent: checking if DHCP is running")
	_, err := a.Helper.DhcpPid()
	if err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}
	err = a.store.addNetIf(&netif)
	if err != nil {
		return agentError(err)
	}
	glog.Info("Agent: creating endpoint routes")
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}
	glog.Info("Agent: provisioning DHCP")
	if err := a.leaseFile.provisionLease(&netif, leaseAdd); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	glog.Info("Agent: provisioning firewall")
	fw, err := firewall.NewFirewall(firewall.ShellexProvider)
	if err != nil {
		return err
	}

	err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
	if err != nil {
		return err
	}

	if err1 := fw.SetEndpoint(netif); err1 != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	/*
		metadata := fw.Metadata()
		chainNames := metadata["chains"].([]string)
		u32filter := metadata["u32filter"]
		hostAddr := a.networkConfig.RomanaGW()

		// Default firewall rules for OpenStack
		inboundChain := chainNames[firewall.InputChainIndex]
		var defaultRules []firewall.FirewallRule

		inboundRule := firewall.NewFirewallRule()
		inboundRule.SetBody(fmt.Sprintf("%s %s", inboundChain, "-m comment --comment DefaultDrop -j DROP"))
		defaultRules = append(defaultRules, inboundRule)

		inboundRule = firewall.NewFirewallRule()
		inboundRule.SetBody(fmt.Sprintf("%s %s", inboundChain, "-m state --state ESTABLISHED -j ACCEPT"))
		defaultRules = append(defaultRules, inboundRule)

		forwardOutChain := chainNames[firewall.ForwardOutChainIndex]
		forwardOutRule := firewall.NewFirewallRule()
		forwardOutRule.SetBody(fmt.Sprintf("%s %s", forwardOutChain, "-m comment --comment Outgoing -j RETURN"))
		defaultRules = append(defaultRules, forwardOutRule)

		forwardInChain := chainNames[firewall.ForwardInChainIndex]
		forwardInRule := firewall.NewFirewallRule()
		forwardInRule.SetBody(fmt.Sprintf("%s %s", forwardInChain, "-m state --state ESTABLISHED -j ACCEPT"))
		defaultRules = append(defaultRules, forwardInRule)

		forwardInRule = firewall.NewFirewallRule()
		forwardInRule.SetBody(fmt.Sprintf("%s ! -s %s -m u32 --u32 %s %s", forwardInChain, hostAddr, u32filter, "-j ACCEPT"))
		defaultRules = append(defaultRules, forwardInRule)

		fw.SetDefaultRules(defaultRules)
	*/

	var rules RuleSet
	switch currentProvider {
	case firewall.ShellexProvider:
		rules = OpenStackShellRules
	case firewall.IPTsaveProvider:
		rules = OpenStackSaveRestoreRules
	default:
		err := fmt.Errorf("Unkown firewall provider in vmUpHandler")
		glog.Error(agentError(err))
		return agentError(err)
	}

	if err := prepareFirewallRules(fw, a.networkConfig, rules, currentProvider); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	if err := fw.ProvisionEndpoint(); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	glog.Info("All good", netif)
	return nil
}

func (a Agent) getFirewallType() firewall.Provider {
	provider, ok := a.config.ServiceSpecific["firewall_provider"].(string)
	if !ok {
		panic("Unable to read firewall_provider from config")
	}

	switch provider {
	case "shellex":
		glog.Infoln("Agent: using ShellexProvider firewall provider")
		return firewall.ShellexProvider
	case "save-restore":
		glog.Infoln("Agent: using IPTsaveProvider firewall provider")
		return firewall.IPTsaveProvider
	default:
		panic(fmt.Sprintf("Unsupported firewall type value %s, supported values are 'shellex' and 'save-restore'", provider))
	}

}
