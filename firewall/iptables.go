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

package firewall

import (
	"fmt"
	"github.com/golang/glog"
	utilexec "github.com/romana/core/pkg/util/exec"
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
)

// Iptables implements romana Firewall using iptables.
type Iptables struct {
	chains        [numberOfDefaultChains]IptablesChain
	u32Filter     string
	chainPrefix   string
	interfaceName string
	Platform      FirewallPlatform
	Store         firewallStore
	os            utilexec.Executable

	// Discovered run-time configuration.
	networkConfig NetConfig
}

// IptablesChain describes state of the particular firewall chain.
type IptablesChain struct {
	baseChain  string
	directions []string
	rules      []string
	chainName  string
}

// NewIptablesChain initializes a new firewall chain.
func NewIptablesChain(baseChain string, direction []string, rules []string, chainName string) *IptablesChain {
	return &IptablesChain{baseChain, direction, rules, chainName}
}

// Collection of firewall rules.
type firewallRules []string

// Add appends a new firewall rule to the collection of firewall rules.
func (r *firewallRules) Add(content string) {
	*r = append(*r, content)
}

// prepareChainName returns a chain name with tenant-segment specific prefix.
func (fw *Iptables) prepareChainName(chainName string) string {
	return fmt.Sprintf("%s%s", fw.chainPrefix, chainName)
}

// makeRules generates rules for given endpoint on given platform
// TODO make platform aware.
func (fw *Iptables) makeRules(netif FirewallEndpoint) error {
	var err error
	fw.u32Filter, fw.chainPrefix, err = fw.prepareU32Rules(netif.GetIP())
	if err != nil {
		// TODO need personalized error here, or even panic
		return err
	}
	fw.interfaceName = netif.GetName()

	// Allow ICMP, DHCP and SSH between host and instances.
	hostAddr := fw.networkConfig.RomanaGW()
	inputRules := []string{
		"-d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67",
	}

	outputRules := []string{
		fmt.Sprintf("-s %s/32 -p udp -m udp --sport 67 --dport 68", hostAddr),
	}

	forwardRules := []string{
		"-m comment --comment Outgoing",
	}

	tenantVectorChainName := fmt.Sprintf("ROMANA-T%d", fw.extractTenantID(ipToInt(netif.GetIP())))
	tenantVectorRules := []string{
		"-m state --state RELATED,ESTABLISHED",
	}

	fw.chains[inputChainIndex] = IptablesChain{"INPUT", []string{"i"}, inputRules, fw.prepareChainName("INPUT")}
	fw.chains[outputChainIndex] = IptablesChain{"OUTPUT", []string{"o"}, outputRules, fw.prepareChainName("OUTPUT")}
	fw.chains[forwardInChainIndex] = IptablesChain{"FORWARD", []string{"i"}, forwardRules, fw.prepareChainName("FORWARD")}
	fw.chains[forwardOutChainIndex] = IptablesChain{"FORWARD", []string{"o"}, tenantVectorRules, tenantVectorChainName}

	return nil
}

// isChainExist verifies if given iptables chain exists.
// Returns true chain exists.
func (fw *Iptables) isChainExist(chain int) bool {
	cmd := "/sbin/iptables"
	args := []string{"-L", fw.chains[chain].chainName}
	output, err := fw.os.Exec(cmd, args)
	if err != nil {
		return false
	}
	glog.Infof("isChainExist(): iptables -L %s returned %s", fw.chains[chain].chainName, string(output))
	return true
}

// isRuleExist verifies if given iptables rule exists.
// Returns true rule exists.
func (fw *Iptables) isRuleExist(ruleSpec []string) bool {
	cmd := "/sbin/iptables"
	args := []string{"-C"}
	args = append(args, ruleSpec...)
	_, err := fw.os.Exec(cmd, args)
	if err != nil {
		return false
	}
	return true
}

// detectMissingChains checks which Iptables chains haven't been created yet.
// Because we do not want to create chains that already exist.
func (fw *Iptables) detectMissingChains() []int {
	var ret []int
	for chain := range fw.chains {
		glog.Infof("Testing chain", chain)
		if !fw.isChainExist(chain) {
			glog.Infof(">> Testing chain success", chain)
			ret = append(ret, chain)
		}
	}
	return ret
}

// CreateChains creates Iptables chains such as
// ROMANA-T0S0-OUTPUT, ROMANA-T0S0-FORWARD, ROMANA-T0S0-INPUT.
func (fw *Iptables) CreateChains(newChains []int) error {
	for chain := range newChains {
		cmd := "/sbin/iptables"
		args := []string{"-N", fw.chains[chain].chainName}
		_, err := fw.os.Exec(cmd, args)
		if err != nil {
			return err
		}
	}
	return nil
}

// opType for DivertTrafficToRomanaIptablesChain
type opDivertTrafficAction int

const (
	installDivertRules opDivertTrafficAction = iota
	removeDivertRules
)

func (d opDivertTrafficAction) String() string {
	var result string
	switch d {
	case installDivertRules:
		result = "Installing divert rules"
	case removeDivertRules:
		result = "Removing divert rules"
	}
	return result
}

// DivertTrafficToRomanaIptablesChain injects iptables rules to send traffic
// into the ROMANA chain.
// We need to do this for each tenant/segment pair as each pair will have different chain name.
func (fw *Iptables) DivertTrafficToRomanaIptablesChain(chain int, opType opDivertTrafficAction) error {
	// Should be like that
	// iptables -A INPUT -i tap1234 -j ROMANA-T0S1-INPUT
	glog.Infof("In DivertTrafficToRomanaIptablesChain() processing chain number %s with action %s", chain, opType)

	var action opIptablesAction
	switch opType {
	case installDivertRules:
		action = ensureLast
	case removeDivertRules:
		action = ensureAbsent
	}

	baseChain := fw.chains[chain].baseChain
	for _, directionLiteral := range fw.chains[chain].directions {
		direction := fmt.Sprintf("-%s", directionLiteral)
		chainName := fw.chains[chain].chainName
		ruleSpec := []string{baseChain, direction, fw.interfaceName, "-j", chainName}

		// First create rule record in database.
		rule, err0 := fw.addIPtablesRule(ruleSpec)
		if err0 != nil {
			glog.Error("In DivertTrafficToRomanaIptablesChain() failed to process chain number", chain)
			return err0
		}

		// Then create actuall rule in the system.
		if err1 := fw.EnsureRule(ruleSpec, action); err1 != nil {
			glog.Error("In DivertTrafficToRomanaIptablesChain() failed to process chain number ", chain)
			return err1
		}

		// Finally, set 'active' flag in database record.
		if err2 := fw.Store.switchIPtablesRule(rule, setRuleActive); err2 != nil {
			glog.Error("In DivertTrafficToRomanaIptablesChain() iptables rule created but activation failed ", rule.Body)
			return err2
		}

	}
	glog.Info("DivertTrafficToRomanaIptablesChain() successfully processed chain number", chain)
	return nil
}

// addIPtablesRule creates new iptable rule in database.
func (fw *Iptables) addIPtablesRule(ruleSpec []string) (*IPtablesRule, error) {
	rule := new(IPtablesRule)
	rule.Body = strings.Join(ruleSpec, " ")
	rule.State = setRuleInactive.String()
	if err := fw.Store.addIPtablesRule(rule); err != nil {
		glog.Error("In addIPtablesRule failed to add ", rule.Body)
		return nil, err
	}

	return rule, nil
}

// CreateRules creates iptables rules for the given Romana chain
// to allow a traffic to flow between the Host and Endpoint.
func (fw *Iptables) CreateRules(chain int) error {
	glog.Info("In CreateRules() for chain", chain)
	for rule := range fw.chains[chain].rules {
		chainName := fw.chains[chain].chainName
		ruleSpec := []string{chainName}
		ruleSpec = append(ruleSpec, strings.Split(fw.chains[chain].rules[rule], " ")...)
		ruleSpec = append(ruleSpec, []string{"-j", "ACCEPT"}...)

		// First create rule record in database.
		rule, err0 := fw.addIPtablesRule(ruleSpec)
		if err0 != nil {
			glog.Error("In CreateRules() create db record for iptables rule ", ruleSpec)
			return err0
		}

		err1 := fw.EnsureRule(ruleSpec, ensureFirst)
		if err1 != nil {
			glog.Error("In CreateRules() failed to create install firewall rule ", ruleSpec)
			return err1
		}

		// Finally, set 'active' flag in database record.
		if err2 := fw.Store.switchIPtablesRule(rule, setRuleActive); err2 != nil {
			glog.Error("In CreateRules() iptables rule created but activation failed ", rule.Body)
			return err2
		}
	}
	glog.Info("Creating firewall rules success")
	return nil
}

// CreateU32Rules creates wildcard iptables rules for the given Romana chain.
// These rules serve to restrict traffic between segments and tenants.
// * Deprecated, outdated *
func (fw *Iptables) CreateU32Rules(chain int) error {
	glog.Info("Creating U32 firewall rules for chain", chain)
	chainName := fw.chains[chain].chainName
	cmd := "/sbin/iptables"
	args := []string{"-A", chainName, "-m", "u32", "--u32", fw.u32Filter, "-j", "ACCEPT"}
	_, err := fw.os.Exec(cmd, args)
	if err != nil {
		glog.Error("Creating U32 firewall rules failed")
		return err
	}
	glog.Info("Creating U32 firewall rules success")
	return nil
}

// CreateDefaultDropRule creates iptables rules to drop all unidentified traffic
// in the given chain
func (fw *Iptables) CreateDefaultDropRule(chain int) error {
	return fw.CreateDefaultRule(chain, targetDrop)
}

// CreateDefaultRule creates iptables rule for a chain with the
// specified target
func (fw *Iptables) CreateDefaultRule(chain int, target string) error {
	glog.Infof("In CreateDefaultRule() %s rules for chain %d", target, chain)
	chainName := fw.chains[chain].chainName
	ruleSpec := []string{chainName, "-j", target}

	// First create rule record in database.
	rule, err0 := fw.addIPtablesRule(ruleSpec)
	if err0 != nil {
		glog.Error("In CreateDefaultRules() create db record for iptables rule ", ruleSpec)
		return err0
	}

	err1 := fw.EnsureRule(ruleSpec, ensureLast)
	if err1 != nil {
		glog.Errorf("In CreateDefaultRules() %s rules failed", target)
		return err1
	}

	// Finally, set 'active' flag in database record.
	if err2 := fw.Store.switchIPtablesRule(rule, setRuleActive); err2 != nil {
		glog.Error("In CreateDefaultRules() iptables rule created but activation failed ", rule.Body)
		return err2
	}

	glog.Info("In CreateDefaultRules() success")
	return nil
}

// prepareTenantSegmentMask returns integer representation of a bitmask
// for tenant+segment bits in pseudo network.
func (fw *Iptables) prepareTenantSegmentMask() uint64 {
	var res uint64
	tenantBits := fw.networkConfig.TenantBits()
	segmentBits := fw.networkConfig.SegmentBits()
	combinedTSBits := tenantBits + segmentBits
	endpointBits := fw.networkConfig.EndpointBits()
	res = ((1 << combinedTSBits) - 1) << endpointBits
	return res
}

// ipToInt transforms IP address from net.IP form to integer form.
// Taken from IPAM/config, should really be in some shared library.
func ipToInt(ip net.IP) uint64 {
	return uint64(ip[12])<<24 | uint64(ip[13])<<16 | uint64(ip[14])<<8 | uint64(ip[15])
}

// PseudoNetNetmaskInt returns integer representation of pseudo net netmask.
func (fw *Iptables) PseudoNetNetmaskInt() (uint64, error) {
	cidr, err := fw.networkConfig.PNetCIDR()
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

// prepareU32Rules generates Iptables rules for U32 iptables module.
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
func (fw *Iptables) prepareU32Rules(ipAddr net.IP) (string, string, error) {
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
func (fw *Iptables) prepareNetmaskBits() (uint64, error) {
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
func (fw *Iptables) extractSegmentID(addr uint64) uint64 {
	endpointBits := fw.networkConfig.EndpointBits()
	segmentBits := fw.networkConfig.SegmentBits()
	sid := (addr >> endpointBits) & ((1 << segmentBits) - 1)
	return sid
}

// extractTenantID extracts tenant id from given the ip address.
// This is possible because tenant id encoded in the ip address.
func (fw *Iptables) extractTenantID(addr uint64) uint64 {
	endpointBits := fw.networkConfig.EndpointBits()
	segmentBits := fw.networkConfig.SegmentBits()
	tenantBits := fw.networkConfig.TenantBits()
	tid := (addr >> (endpointBits + segmentBits)) & ((1 << tenantBits) - 1)
	return tid
}

// ProvisionEndpoint creates iptables rules for given endpoint in given platform.
func (fw Iptables) ProvisionEndpoint(netif FirewallEndpoint) error {
	glog.Info("In ProvisionEndpoint()")
	var err error

	if err = fw.makeRules(netif); err != nil {
		return err
	}

	switch fw.Platform {
	case KubernetesPlatform:
		err = fw.provisionK8SIptablesRules()
	case OpenStackPlatform:
		err = fw.provisionIptablesRules()
	}

	return err
}

// cleanupIptables deletes stale iptables rules when interface goes away
func (fw Iptables) Cleanup(netif FirewallEndpoint) error {
	if err := fw.deleteIPtablesRulesBySubstring(netif.GetName()); err != nil {
		glog.Error("In cleanupFirewall() failed to clean firewall for %s ", netif.GetName())
		return err
	}

	return nil
}

// deleteIPtablesRulesBySubstring uninstalls iptables rules matching given
// substring and deletes them from database. Has no effect on 'inactive' rules.
func (fw *Iptables) deleteIPtablesRulesBySubstring(substring string) error {
	rules, err := fw.Store.findIPtablesRules(substring)
	if err != nil {
		return err
	}

	for _, rule := range *rules {
		if rule.State == setRuleInactive.String() {
			continue
		}

		err = fw.deleteIPtablesRule(&rule)
		if err != nil {
			return err
		}
	}

	return nil
}

func (fw *Iptables) deleteIPtablesRule(rule *IPtablesRule) error {
	if err := fw.Store.switchIPtablesRule(rule, setRuleInactive); err != nil {
		glog.Error("In deleteIPtablesRule() failed to deactivate the rule", rule.Body)
		return err
	}

	if err1 := fw.EnsureRule(strings.Split(rule.Body, " "), ensureAbsent); err1 != nil {
		glog.Errorf("In deleteIPtablesRule() rule %s set inactive but failed to uninstall", rule.Body)
		return err1
	}

	if err2 := fw.Store.deleteIPtablesRule(rule); err2 != nil {
		glog.Errorf("In deleteIPtablesRule() rule %s set inactive and uninstalled but failed to delete DB record", rule.Body)
		return err2
	}
	return nil
}

// EnsureRule verifies if given iptables rule exists and creates if it's not.
func (fw Iptables) EnsureRule(ruleSpec []string, opType opIptablesAction) error {
	ruleExists := fw.isRuleExist(ruleSpec)
	cmd := "/sbin/iptables"
	args := []string{}

	if ruleExists && opType == ensureAbsent {
		args = append(args, []string{"-D"}...)

	} else if !ruleExists {

		switch opType {
		case ensureLast:
			args = append(args, []string{"-A"}...)
		case ensureFirst:
			args = append(args, []string{"-I"}...)
		}
	} else {
		glog.Infof("In EnsureRule - nothing to do ", ruleSpec)
		return nil
	}

	args = append(args, ruleSpec...)
	_, err := fw.os.Exec(cmd, args)
	if err != nil {
		glog.Errorf("%s filed %s", opType, ruleSpec)
	} else {
		glog.Infof("%s success %s", opType, ruleSpec)
	}

	return err
}

// ListRules implemets Firewall interface
func (fw Iptables) ListRules() ([]IPtablesRule, error) {
	return fw.Store.listIPtablesRules()
}
