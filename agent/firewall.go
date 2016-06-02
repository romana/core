// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// firewall.go is a Firewall manager,
// as of now responsibilities of the Firewall manager is to
// 1. Create per tenant per segment chains
// 2. Divert traffic from base chains into ones created above
// 3. Install Firewall rules into managed chains (restrictive by default)
// 3.1 There is a set of permissive rules per chain
// 3.2 There is also u32 rule per chain that allows traffic between tenant endpoints
//
// Firewall created per user request as follows
// - Firewall := NewFirewall(NetIf)
// where NetIf is a struct defined in netif.go
//
// There are 4 public function available
// - Firewall.CreateChains() - creates managed Firewall chains
// - Firewall.DivertTrafficToRomanaIptablesChain() - diverts traffic to/from/via interface
// - Firewall.CreateRules() - installs basic permissive rules
// - Firewall.CreateU32Rules() - installs u32 rules

package agent

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	numberOfDefaultChains = 4 // INPUT,OUTPUT,FORWARD_IN,FORWARD_OUT,TENANT_VECTOR
	inputChainIndex       = 0
	outputChainIndex      = 1
	forwardInChainIndex   = 2
	forwardOutChainIndex  = 3

	targetDrop   = "DROP"
	targetAccept = "ACCEPT"

	bottomRule = 0
	topRule    = 1
)

// Firewall describes state of firewall rules for the given endpoint.
// Currently methods of this type have no critical sections because
// Firewall won't do anything if per-tenant chains already created.
// But any new features must be safe for concurrent execution.
type Firewall struct {
	chains        [numberOfDefaultChains]FirewallChain
	u32Filter     string
	chainPrefix   string
	interfaceName string
	Agent         *Agent // access field to Agent
}

// FirewallChain describes state of the particular firewall chain.
type FirewallChain struct {
	baseChain  string
	directions []string
	rules      []string
	chainName  string
}

// NewFirewallChain initializes a new firewall chain.
func NewFirewallChain(baseChain string, direction []string, rules []string, chainName string) *FirewallChain {
	return &FirewallChain{baseChain, direction, rules, chainName}
}

// NewFirewall returns fully initialized firewall struct, with rules and chains
// configured for given endpoint.
func NewFirewall(netif NetIf, agent *Agent) (*Firewall, error) {
	fw := new(Firewall)
	fw.Agent = agent
	if err := fw.Init(netif); err != nil {
		return nil, err
	}
	return fw, nil
}

// Collection of firewall rules.
type firewallRules []string

// Add appends a new firewall rule to the collection of firewall rules.
func (r *firewallRules) Add(content string) {
	*r = append(*r, content)
}

// prepareChainName returns a chain name with tenant-segment specific prefix.
func (fw *Firewall) prepareChainName(chainName string) string {
	return fmt.Sprintf("%s%s", fw.chainPrefix, chainName)
}

// Init initializes current firewall with a data from the given endpoint.
func (fw *Firewall) Init(netif NetIf) error {
	var err error
	fw.u32Filter, fw.chainPrefix, err = fw.prepareU32Rules(netif.IP)
	if err != nil {
		// TODO need personalized error here, or even panic
		return err
	}
	fw.interfaceName = netif.Name

	// Allow ICMP, DHCP and SSH between host and instances.
	hostAddr := fw.Agent.networkConfig.romanaGW
	inputRules := []string{
		"-d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67",
	}

	outputRules := []string{
		fmt.Sprintf("-s %s/32 -p udp -m udp --sport 67 --dport 68", hostAddr),
	}

	forwardRules := []string{
		"-m comment --comment Outgoing",
	}

	tenantVectorChainName := fmt.Sprintf("ROMANA-T%d", fw.extractTenantID(ipToInt(netif.IP)))
	tenantVectorRules := []string{
		"-m state --state RELATED,ESTABLISHED",
	}

	fw.chains[inputChainIndex] = FirewallChain{"INPUT", []string{"i"}, inputRules, fw.prepareChainName("INPUT")}
	fw.chains[outputChainIndex] = FirewallChain{"OUTPUT", []string{"o"}, outputRules, fw.prepareChainName("OUTPUT")}
	fw.chains[forwardInChainIndex] = FirewallChain{"FORWARD", []string{"i"}, forwardRules, fw.prepareChainName("FORWARD")}
	fw.chains[forwardOutChainIndex] = FirewallChain{"FORWARD", []string{"o"}, tenantVectorRules, tenantVectorChainName}

	return nil
}

// isChainExist verifies if given iptables chain exists.
// Returns true chain exists.
func (fw *Firewall) isChainExist(chain int) bool {
	cmd := "/sbin/iptables"
	args := []string{"-L", fw.chains[chain].chainName}
	output, err := fw.Agent.Helper.Executor.Exec(cmd, args)
	if err != nil {
		return false
	}
	log.Printf("isChainExist(): iptables -L %s returned %s", fw.chains[chain].chainName, string(output))
	return true
}

// isRuleExist verifies if given iptables rule exists.
// Returns true rule exists.
func (fw *Firewall) isRuleExist(ruleSpec []string) bool {
	cmd := "/sbin/iptables"
	args := []string{"-C"}
	args = append(args, ruleSpec...)
	_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
	if err != nil {
		return false
	}
	return true
}

// detectMissingChains checks which Firewall chains haven't been created yet.
// Because we do not want to create chains that already exist.
func (fw *Firewall) detectMissingChains() []int {
	var ret []int
	for chain := range fw.chains {
		log.Print("Testing chain", chain)
		if !fw.isChainExist(chain) {
			log.Print(">> Testing chain success", chain)
			ret = append(ret, chain)
		}
	}
	return ret
}

// CreateChains creates Firewall chains such as
// ROMANA-T0S0-OUTPUT, ROMANA-T0S0-FORWARD, ROMANA-T0S0-INPUT.
func (fw *Firewall) CreateChains(newChains []int) error {
	for chain := range newChains {
		cmd := "/sbin/iptables"
		args := []string{"-N", fw.chains[chain].chainName}
		_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
		if err != nil {
			return err
		}
	}
	return nil
}

// ensureIptablesRule verifies if given iptables rule exists and creates if it's not.
func (fw *Firewall) ensureIptablesRule(ruleSpec []string, ruleOrder int) error {
	if !fw.isRuleExist(ruleSpec) {
		cmd := "/sbin/iptables"
		args := []string{}

		switch ruleOrder {
		case bottomRule:
			args = append(args, []string{"-A"}...)
		case topRule:
			args = append(args, []string{"-I"}...)
		}

		args = append(args, ruleSpec...)
		_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
		if err != nil {
			log.Print("Creating iptables rule failed ", ruleSpec)
			return err
		}
		log.Print("Rule created ", ruleSpec)
	} else {
		log.Print("Rule already exist ", ruleSpec)
	}
	return nil
}

// DivertTrafficToRomanaIptablesChain injects iptables rules to send traffic
// into the ROMANA chain.
// We need to do this for each tenant/segment pair as each pair will have different chain name.
func (fw *Firewall) DivertTrafficToRomanaIptablesChain(chain int) error {
	// Should be like that
	// iptables -A INPUT -i tap1234 -j ROMANA-T0S1-INPUT
	log.Print("Diverting traffic into chain number ", chain)
	baseChain := fw.chains[chain].baseChain
	for _, directionLiteral := range fw.chains[chain].directions {
		direction := fmt.Sprintf("-%s", directionLiteral)
		chainName := fw.chains[chain].chainName
		ruleSpec := []string{baseChain, direction, fw.interfaceName, "-j", chainName}
		if err := fw.ensureIptablesRule(ruleSpec, bottomRule); err != nil {
			log.Print("Diverting traffic failed", chain)
			return err
		}
	}
	log.Print("Diverting traffic success", chain)
	return nil
}

// CreateRules creates iptables rules for the given Romana chain
// to allow a traffic to flow between the Host and Endpoint.
func (fw *Firewall) CreateRules(chain int) error {
	log.Print("Creating firewall rules for chain", chain)
	for rule := range fw.chains[chain].rules {
		chainName := fw.chains[chain].chainName
		/*
			cmd := "/sbin/iptables"
			args := []string{"-A", chainName}
			args = append(args, strings.Split(fw.chains[chain].rules[rule], " ")...)
			args = append(args, []string{"-j", "ACCEPT"}...)
			_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
		*/
		ruleSpec := []string{chainName}
		ruleSpec = append(ruleSpec, strings.Split(fw.chains[chain].rules[rule], " ")...)
		ruleSpec = append(ruleSpec, []string{"-j", "ACCEPT"}...)
		err := fw.ensureIptablesRule(ruleSpec, topRule)
		if err != nil {
			log.Print("Creating firewall rules failed")
			return err
		}
	}
	log.Print("Creating firewall rules success")
	return nil
}

// CreateU32Rules creates wildcard iptables rules for the given Romana chain.
// These rules serve to restrict traffic between segments and tenants.
func (fw *Firewall) CreateU32Rules(chain int) error {
	log.Print("Creating U32 firewall rules for chain", chain)
	chainName := fw.chains[chain].chainName
	cmd := "/sbin/iptables"
	args := []string{"-A", chainName, "-m", "u32", "--u32", fw.u32Filter, "-j", "ACCEPT"}
	_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
	if err != nil {
		log.Print("Creating U32 firewall rules failed")
		return err
	}
	log.Print("Creating U32 firewall rules success")
	return nil
}

// CreateDefaultDropRule creates iptables rules to drop all unidentified traffic
// in the given chain
func (fw *Firewall) CreateDefaultDropRule(chain int) error {
	return fw.CreateDefaultRule(chain, targetDrop)
}

// CreateDefaultRule creates iptables rule for a chain with the
// specified target
func (fw *Firewall) CreateDefaultRule(chain int, target string) error {
	log.Printf("Creating default %s rules for chain %d", target, chain)
	chainName := fw.chains[chain].chainName
	/*
		cmd := "/sbin/iptables"
		args := []string{"-A", chainName, "-j", target}
		_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
	*/
	ruleSpec := []string{chainName, "-j", target}
	err := fw.ensureIptablesRule(ruleSpec, bottomRule)
	if err != nil {
		log.Printf("Creating default %s rules failed", target)
		return err
	}
	log.Print("Creating default drop rules success")
	return nil
}

// prepareTenantSegmentMask returns integer representation of a bitmask
// for tenant+segment bits in pseudo network.
func (fw *Firewall) prepareTenantSegmentMask() uint64 {
	var res uint64
	tenantBits := fw.Agent.networkConfig.TenantBits()
	segmentBits := fw.Agent.networkConfig.SegmentBits()
	combinedTSBits := tenantBits + segmentBits
	endpointBits := fw.Agent.networkConfig.EndpointBits()
	res = ((1 << combinedTSBits) - 1) << endpointBits
	return res
}

// ipToInt transforms IP address from net.IP form to integer form.
// Taken from IPAM/config, should really be in some shared library.
func ipToInt(ip net.IP) uint64 {
	return uint64(ip[12])<<24 | uint64(ip[13])<<16 | uint64(ip[14])<<8 | uint64(ip[15])
}

// PseudoNetNetmaskInt returns integer representation of pseudo net netmask.
func (fw *Firewall) PseudoNetNetmaskInt() (uint64, error) {
	cidr, err := fw.Agent.networkConfig.PNetCIDR()
	if err != nil {
		return 0, err
	}
	pNetMaskInt, err := MaskToInt(cidr.Mask)
	if err != nil {
		return 0, err
	}
	return pNetMaskInt, nil
}

// MaskToInt converts net.IPMask to integer.
// TODO Not strictly firewall method, maybe put in different place.
func MaskToInt(mask net.IPMask) (uint64, error) {
	var imask uint64
	m, err := strconv.ParseInt(mask.String(), 16, 64)
	imask = uint64(m)
	if err != nil {
		return 0, err
	}
	return imask, nil
}

// prepareU32Rules generates Firewall rules for U32 iptables module.
// This rules implemet Romana tenant/segment filtering
//   Return the filter rules for the iptables u32 module.
//   Goal: Filter out any traffic that does not have the same tenant and segment
//   bits in the destination address as the interface itself.
//   These bits can be extracted from the IP address: This is the address that
//   we are assigning to the interface. The function is to be called when the
//   interface is set up. The passed-in address therefore can be trusted: It is
//   not taken from a packet.
//      Example:
//      ipAddr = "10.0.1.4"
//
//      Return:
//      filter = '12&0xFF00FF00=0xA000100 && 16&0xFF00FF00=0xA000100'
//      chainPrefix = 'ROMANA-T0S1-'
//
//   TODO Refactor chain-prefix routine into separate function (prepareChainPrefix).
//   Also return the chain-prefix we'll use for this interface. This is
//   typically a string such as:
//       ROMANA-T<tenant-id>S<segment-id>-
//   For example, with tenant 1 and segment 2, this would be:
//       ROMANA-T1S2-
func (fw *Firewall) prepareU32Rules(ipAddr net.IP) (string, string, error) {
	fullMask, err := fw.prepareNetmaskBits()
	if err != nil {
		return "", "", err
	}
	addr := ipToInt(ipAddr)
	if err != nil {
		return "", "", err
	}
	filter1 := fmt.Sprintf("0x%X=0x%X", fullMask, addr&fullMask)
	filter := fmt.Sprintf("12&%s && 16&%s", filter1, filter1)
	tenantID := fw.extractTenantID(addr)
	segmentID := fw.extractSegmentID(addr)
	chainPrefix := fmt.Sprintf("ROMANA-T%dS%d-", tenantID, segmentID)
	return filter, chainPrefix, nil
}

// prepareNetmaskBits returns integer representation of pseudo network bitmask.
// Used to prepare u32 firewall rules that would match ip addresses belonging
// to given tenant/segment pair.
func (fw *Firewall) prepareNetmaskBits() (uint64, error) {
	iCidrMask, err := fw.PseudoNetNetmaskInt()
	if err != nil {
		return 0, err
	}
	combinedTSMask := fw.prepareTenantSegmentMask()
	res := iCidrMask | combinedTSMask
	return res, nil
}

// extractSegmentID extracts segment id from the given ip address.
// This is possible because segment id encoded in the ip address.
func (fw *Firewall) extractSegmentID(addr uint64) uint64 {
	endpointBits := fw.Agent.networkConfig.EndpointBits()
	segmentBits := fw.Agent.networkConfig.SegmentBits()
	sid := (addr >> endpointBits) & ((1 << segmentBits) - 1)
	return sid
}

// extractTenantID extracts tenant id from given the ip address.
// This is possible because tenant id encoded in the ip address.
func (fw *Firewall) extractTenantID(addr uint64) uint64 {
	endpointBits := fw.Agent.networkConfig.EndpointBits()
	segmentBits := fw.Agent.networkConfig.SegmentBits()
	tenantBits := fw.Agent.networkConfig.TenantBits()
	tid := (addr >> (endpointBits + segmentBits)) & ((1 << tenantBits) - 1)
	return tid
}

func (fw *Firewall) deleteChains() error {
	errStr := ""
	cmd := "/sbin/iptables"

	// Save our chains here...
	chainMap := make(map[string]string)
	for chain := range fw.chains {
		chainName := fw.chains[chain].chainName
		chainMap[chainName] = chainName
	}

	output, err := fw.Agent.Helper.Executor.Exec(cmd, []string{"-L"})
	if err != nil {
		return err
	}
	// Parse output of iptables listing
	lines := strings.Split(string(output), "\n")
	curChain := ""
	skipLine := false
	ruleCnt := 0
	var curRules []int
	for lineNo, line := range lines {
		if skipLine {
			skipLine = false
			continue
		}
		line = strings.TrimSpace(line)
		// Skip an empty line
		if line == "" {
			continue
		}
		words := strings.Split(line, " ")
		if len(words) == 0 {
			continue
		}
		if words[0] == "Chain" {
			// Entering a new chain
			if curChain != "" {
				// We may have rules to delete from the previously processed chain.
				if len(curRules) > 0 {
					log.Printf("Process %d rules to delete for chain %s: %v", len(curRules), curChain, curRules)
					// Delete rules in reverse order (so that we don't change rule number
					// on the fly)
					for i := len(curRules) - 1; i >= 0; i-- {
						ruleNo := curRules[i]
						ruleNoStr := strconv.Itoa(ruleNo)
						args := []string{"-D", curChain, ruleNoStr}
						out2, err := fw.Agent.Helper.Executor.Exec(cmd, args)
						if len(out2) > 0 {
							log.Printf("executing iptables -D %s %d: %s", curChain, ruleNo, string(out2))
						}
						if err != nil {
							log.Printf("Deleting rule %d: %v", ruleNo, err)
							return err
						}
						log.Printf("Deleting rule %d: OK", ruleNo)
					}
					curRules = make([]int, 0)
					ruleCnt = 0
				}
			}
			curChain = words[1]
			ruleCnt = 0
			curRules = make([]int, 0)
			if chainMap[curChain] == curChain {
				log.Printf("Chain %s is ours, skipping for now...", curChain)
				continue
			}
			log.Printf("Entering chain %s on line %d", curChain, lineNo)
			skipLine = true
			continue
		}

		refChain := words[0]
		ruleCnt++

		if chainMap[refChain] == refChain {
			log.Printf("Chain %s refers to our chain %s in rule %d (line %d), adding to removal list", curChain, refChain, ruleCnt, lineNo)
			curRules = append(curRules, ruleCnt)
		}
	}

	for chain := range fw.chains {
		chainName := fw.chains[chain].chainName
		if !fw.isChainExist(chain) {
			log.Printf("Chain %d: %s does not really exist.", chain, chainName)
			continue
		}
		log.Printf("Deleting chain %d (%s)", chain, chainName)
		args := []string{"-F", chainName}
		out, err := fw.Agent.Helper.Executor.Exec(cmd, args)
		if len(out) > 0 {
			log.Printf("iptables -F said %s", string(out))
		}
		if err != nil {
			errStr += fmt.Sprintf("Error executing iptables --flush %s: %v. ", chainName, err)
			continue
		}

		args = []string{"-X", chainName}
		out, err = fw.Agent.Helper.Executor.Exec(cmd, args)
		if len(out) > 0 {
			log.Printf("iptables -X %s said %s", chainName, string(out))
		}
		if err != nil {
			errStr += fmt.Sprintf("Error executing iptables -X %s: %v. ", chainName, err)

		}
	}
	if errStr == "" {
		return nil
	}
	return agentErrorString(errStr)
}

// provisionFirewallRules provisions rules for a new pod in Kubernetes.
// Depending on the fullIsolation flag, the rule is specified to either
// DROP or ALLOW all traffic.
func provisionK8SFirewallRules(netReq NetworkRequest, agent *Agent) error {
	log.Print("Firewall: Initializing")
	fw, err := NewFirewall(netReq.NetIf, agent)
	if err != nil {
		log.Fatal("Failed to initialize firewall ", err)
	}

	/*
		err = fw.deleteChains()
		if err != nil {
			return err
		}
	*/
	missingChains := fw.detectMissingChains()
	log.Print("Firewall: creating chains")
	err = fw.CreateChains(missingChains)
	if err != nil {
		return err
	}
	for chain := range fw.chains {
		if err := fw.CreateRules(chain); err != nil {
			return err
		}
	}

	if err := fw.CreateDefaultDropRule(forwardOutChainIndex); err != nil {
		return err
	}

	for chain := range fw.chains {
		if err := fw.DivertTrafficToRomanaIptablesChain(chain); err != nil {
			return err
		}
	}

	return nil
}

// provisionFirewallRules orchestrates Firewall to satisfy request
// to provision new endpoint.
// Creates per-tenant, per-segment iptables chains, diverts
// all traffic to/from/through netif.name interface to a proper chains.
// Currently tested with Romana ML2 driver.
func provisionFirewallRules(netif NetIf, agent *Agent) error {
	log.Print("Firewall: Initializing")
	fw, err := NewFirewall(netif, agent)
	if err != nil {
		log.Fatal("Failed to initialize firewall ", err)
	}

	missingChains := fw.detectMissingChains()
	log.Print("Firewall: creating chains")
	err = fw.CreateChains(missingChains)
	if err != nil {
		return err
	}
	for chain := range missingChains {
		if err := fw.CreateRules(chain); err != nil {
			return err
		}
		if err := fw.CreateDefaultDropRule(chain); err != nil {
			return err
		}
	}

	for chain := range fw.chains {
		if err := fw.DivertTrafficToRomanaIptablesChain(chain); err != nil {
			return err
		}
	}

	return nil
}
