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

// statusHandler reports operational statistics.
func (a *Agent) statusHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	fw, err := firewall.NewFirewall(firewall.ShellexProvider)
	if err != nil {
		return nil, err
	}

	err = fw.Init(a.Helper.Executor, a.store, a.networkConfig)
	if err != nil {
		return nil, err
	}

	iptablesRules, err := fw.ListRules()
	if err != nil {
		return nil, err
	}
	return iptablesRules, nil
}

// podDownHandler cleans up after pod deleted.
func (a *Agent) podDownHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	glog.V(1).Infoln("Agent: Entering podDownHandler()")
	netReq := input.(*NetworkRequest)
	netif := netReq.NetIf

	// We need new firewall instance here to use it's Cleanup()
	// to uninstall firewall rules related to the endpoint.
	fw, err := firewall.NewFirewall(firewall.ShellexProvider)
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
	netif := input.(*NetIf)
	glog.V(1).Infof("In vmDownHandler() with Name %s, IP %s Mac %s\n", netif.Name, netif.IP, netif.Mac)

	// We need new firewall instance here to use it's Cleanup()
	// to uninstall firewall rules related to the endpoint.
	fw, err := firewall.NewFirewall(firewall.ShellexProvider)
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

	metadata := fw.Metadata()
	chainNames := metadata["chains"].([]string)
	hostAddr := a.networkConfig.RomanaGW()
	hostMask, _ := a.networkConfig.RomanaGWMask().Size()

	// Default firewall rules for Kubernetes
	// Allow ICMP, and SSH between host and instances.
	var defaultRules []firewall.FirewallRule

	// ProvisionEndpoint applies default rules in reverse order
	// so DROP goes first
	inboundChain := chainNames[firewall.InputChainIndex]
	inboundRule := firewall.NewFirewallRule()
	inboundRule.SetBody(fmt.Sprintf("%s -d %s/%d %s", inboundChain, hostAddr, hostMask, "-j DROP"))
	defaultRules = append(defaultRules, inboundRule)

	inboundRule = firewall.NewFirewallRule()
	inboundRule.SetBody(fmt.Sprintf("%s %s", inboundChain, "-p icmp --icmp-type 0 -j ACCEPT"))
	defaultRules = append(defaultRules, inboundRule)

	forwardInChain := chainNames[firewall.ForwardInChainIndex]
	forwardInRule := firewall.NewFirewallRule()
	forwardInRule.SetBody(fmt.Sprintf("%s %s", forwardInChain, "-m comment --comment Outgoing -j ACCEPT"))
	defaultRules = append(defaultRules, forwardInRule)

	forwardOutChain := chainNames[firewall.ForwardOutChainIndex]
	forwardOutRule := firewall.NewFirewallRule()
	forwardOutRule.SetBody(fmt.Sprintf("%s %s", forwardOutChain, "-m state --state RELATED,ESTABLISHED -j ACCEPT"))
	defaultRules = append(defaultRules, forwardOutRule)

	fw.SetDefaultRules(defaultRules)

	if err := fw.ProvisionEndpoint(); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	glog.Info("Agent: All good", netif)
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
	glog.Info("Agent: creating endpoint routes")
	if err := a.Helper.ensureRouteToEndpoint(&netif); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}
	glog.Info("Agent: provisioning DHCP")
	if err := a.leaseFile.provisionLease(&netif); err != nil {
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

	metadata := fw.Metadata()
	chainNames := metadata["chains"].([]string)
	u32filter := metadata["u32filter"]
	hostAddr := a.networkConfig.RomanaGW()
	hostMask, _ := a.networkConfig.RomanaGWMask().Size()

	// Default firewall rules for OpenStack
	// Allow ICMP, DHCP and SSH between host and instances.
	inboundChain := chainNames[firewall.InputChainIndex]
	var defaultRules []firewall.FirewallRule

	inboundRule := firewall.NewFirewallRule()
	inboundRule.SetBody(fmt.Sprintf("%s -d %s/%d %s", inboundChain, hostAddr, hostMask, "-j DROP"))
	defaultRules = append(defaultRules, inboundRule)

	inboundRule = firewall.NewFirewallRule()
	inboundRule.SetBody(fmt.Sprintf("%s %s", inboundChain, "-d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67 -j ACCEPT"))
	defaultRules = append(defaultRules, inboundRule)

	inboundRule = firewall.NewFirewallRule()
	inboundRule.SetBody(fmt.Sprintf("%s %s", inboundChain, "-p tcp --sport 22 -j ACCEPT"))
	defaultRules = append(defaultRules, inboundRule)

	inboundRule = firewall.NewFirewallRule()
	inboundRule.SetBody(fmt.Sprintf("%s %s", inboundChain, "-p icmp --icmp-type 0 -j ACCEPT"))
	defaultRules = append(defaultRules, inboundRule)

	outboundChain := chainNames[firewall.OutputChainIndex]
	outboundRule := firewall.NewFirewallRule()
	outboundRule.SetBody(fmt.Sprintf("%s -s %s/32 -p udp -m udp --sport 67 --dport 68 -j ACCEPT", outboundChain, hostAddr))
	defaultRules = append(defaultRules, outboundRule)

	outboundRule = firewall.NewFirewallRule()
	outboundRule.SetBody(fmt.Sprintf("%s %s", outboundChain, "-p tcp --dport 22 -j ACCEPT"))
	defaultRules = append(defaultRules, outboundRule)

	forwardInChain := chainNames[firewall.ForwardInChainIndex]
	forwardInRule := firewall.NewFirewallRule()
	forwardInRule.SetBody(fmt.Sprintf("%s %s", forwardInChain, "-m comment --comment Outgoing -j ACCEPT"))
	defaultRules = append(defaultRules, forwardInRule)

	forwardOutChain := chainNames[firewall.ForwardOutChainIndex]
	forwardOutRule := firewall.NewFirewallRule()
	forwardOutRule.SetBody(fmt.Sprintf("%s %s", forwardOutChain, "-m state --state RELATED,ESTABLISHED -j ACCEPT"))
	defaultRules = append(defaultRules, forwardOutRule)

	forwardOutRule = firewall.NewFirewallRule()
	forwardOutRule.SetBody(fmt.Sprintf("%s -m u32 --u32 %s %s", forwardOutChain, u32filter, "-j ACCEPT"))
	defaultRules = append(defaultRules, forwardOutRule)

	fw.SetDefaultRules(defaultRules)

	if err := fw.ProvisionEndpoint(); err != nil {
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
