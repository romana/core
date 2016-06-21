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
	fw, err := firewall.NewFirewall(a.Helper.Executor, a.store, a.networkConfig, firewall.OpenStackEnvironment)
	if err != nil {
		return nil, err
	}

	iptablesRules, err := fw.ListRules()
	if err != nil {
		return nil, err
	}
	return iptablesRules, nil
}

// k8sPodDownHandler cleans up after pod deleted.
func (a *Agent) k8sPodDownHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	glog.Infoln("Agent: Entering k8sPodDownHandler()")
	netReq := input.(*NetworkRequest)
	netif := netReq.NetIf

	fw, err := firewall.NewFirewall(a.Helper.Executor, a.store, a.networkConfig, firewall.KubernetesEnvironment)
	if err != nil {
		return nil, err
	}

	err = fw.Cleanup(netif)
	if err != nil {
		return nil, err
	}

	// Spawn new thread to process the request
	glog.Infof("Agent: Got request for network configuration: %v\n", netReq)

	return "OK", nil
}

// k8sPodUpHandler handles HTTP requests for endpoints provisioning.
func (a *Agent) k8sPodUpHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	glog.Infof("Agent: Entering k8sPodUpHandler()")
	netReq := input.(*NetworkRequest)

	glog.Infof("Agent: Got request for network configuration: %v\n", netReq)
	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.k8sPodUpHandle(*netReq)

	// TODO I wonder if this should actually return something like a
	// link to a status of this request which will later get updated
	// with success or failure -- Greg.
	return "OK", nil
}

// index handles HTTP requests for endpoints provisioning.
// Currently tested with Romana ML2 driver.
// TODO index should be reserved for an actual index, while this function
// need to be renamed as interfaceHandler and need to respond on it's own url.
func (a *Agent) index(input interface{}, ctx common.RestContext) (interface{}, error) {
	// Parse out NetIf form the request
	netif := input.(*NetIf)

	glog.Infof("Got interface: Name %s, IP %s Mac %s\n", netif.Name, netif.IP, netif.Mac)
	// Spawn new thread to process the request

	// TODO don't know if fork-bombs are possible in go but if they are this
	// need to be refactored as buffered channel with fixed pool of workers
	go a.interfaceHandle(*netif)

	// TODO I wonder if this should actually return something like a
	// link to a status of this request which will later get updated
	// with success or failure -- Greg.
	return "OK", nil
}

// k8sPodUpHandle does a number of operations on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Creates ip route pointing new interface
// 3. Provisions firewall rules
func (a *Agent) k8sPodUpHandle(netReq NetworkRequest) error {
	glog.Info("Agent: Entering k8sPodUpHandle()")

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
	fw, err := firewall.NewFirewall(a.Helper.Executor, a.store, a.networkConfig, firewall.KubernetesEnvironment)
	if err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	// Allow ICMP, DHCP and SSH between host and instances.
	hostAddr := a.networkConfig.RomanaGW()
	inputRules := []*firewall.IPtablesRule{
		&firewall.IPtablesRule{
			Body: "-d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67",
		},
	}
	//	fw.SetDefaultRules(inputRules, firewall.InputChainIndex)

	outputRules := []*firewall.IPtablesRule{
		&firewall.IPtablesRule{
			Body: fmt.Sprintf("-s %s/32 -p udp -m udp --sport 67 --dport 68", hostAddr),
		},
	}
	//	fw.SetDefaultRules(outputRules, firewall.OutputChainIndex)

	forwardRules := []*firewall.IPtablesRule{
		&firewall.IPtablesRule{
			Body: "-m comment --comment Outgoing",
		},
	}
	//	fw.SetDefaultRules(forwardRules, firewall.ForwardInChainIndex)

	tenantVectorRules := []*firewall.IPtablesRule{
		&firewall.IPtablesRule{
			Body: "-m state --state RELATED,ESTABLISHED",
		},
	}
	//	fw.SetDefaultRules(tenantVectorRules, firewall.ForwardOutChainIndex)

	if err := fw.ProvisionEndpoint(netif, inputRules, outputRules, forwardRules, tenantVectorRules); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	glog.Info("Agent: All good", netif)
	return nil
}

// interfaceHandle does a number of operations on given endpoint to ensure
// it's connected:
// 1. Ensures interface is ready
// 2. Checks if DHCP is running
// 3. Creates ip route pointing new interface
// 4. Provisions static DHCP lease for new interface
// 5. Provisions firewall rules
func (a *Agent) interfaceHandle(netif NetIf) error {
	glog.Info("Agent: processing request to provision new interface")
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
	fw, err := firewall.NewFirewall(a.Helper.Executor, a.store, a.networkConfig, firewall.OpenStackEnvironment)
	if err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	if err := fw.ProvisionEndpoint(netif); err != nil {
		glog.Error(agentError(err))
		return agentError(err)
	}

	glog.Info("All good", netif)
	return nil
}
