package agent

// This file is a Firewall manager,
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
// - Firewall.DiverTrafficToPaniIptablesChain() - diverts traffic to/from/via interface
// - Firewall.CreateRules() - installs basic permissive rules
// - Firewall.CreateU32Rules() - installs u32 rules

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	numberOfDefaultChains = 3 // INPUT,OUTPUT,FORWARD
	inputChainIndex       = 0
	outputChainIndex      = 1
	forwardChainIndex     = 2
)

// Firewall type describes state of firewall rules for the given endpoint.
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
	baseChain string
	direction string
	rules     []string
	chainName string
}

// NewFirewallChain initializes new a firewall chain.
func NewFirewallChain(baseChain string, direction string, rules []string, chainName string) *FirewallChain {
	return &FirewallChain{baseChain, direction, rules, chainName}
}

// NewFirewall returns fully initialized firewall struct.
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
	fw.u32Filter, fw.chainPrefix, err = fw.prepareU32Rules(netif.ip)
	if err != nil {
		// TODO need personalized error here, or even panic
		return err
	}
	fw.interfaceName = netif.name

	// Default permissive rules to allow ssh/ICMP
	// from the Host to the Endpoint. Normally wildcard U32 filter would
	// block all the Host to Endpoint traffic.
	inputRules := new(firewallRules)
	inputRules.Add(fmt.Sprintf("-d %s", fw.Agent.config.CurrentHostIP))
	inputRules.Add(fmt.Sprintf("-d %s/%d", fw.Agent.config.CurrentHostGW, fw.Agent.config.CurrentHostGWNetSize))
	inputRules.Add("-p udp --sport 68 --dport 67 -d 255.255.255.255")
	inputRules.Add(fmt.Sprintf("-p tcp -m tcp --sport 22 -d %s", fw.Agent.config.CurrentHostIP))

	outputRules := new(firewallRules)
	outputRules.Add(fmt.Sprintf("-d %s", fw.Agent.config.CurrentHostIP))
	outputRules.Add(fmt.Sprintf("-d %s/%d", fw.Agent.config.CurrentHostGW, fw.Agent.config.CurrentHostGWNetSize))
	outputRules.Add(fmt.Sprintf("-p tcp -m tcp --sport 22 -d %s", fw.Agent.config.CurrentHostIP))

	forwardRules := new(firewallRules)

	c1 := NewFirewallChain("INPUT", "i", *inputRules, fw.prepareChainName("INPUT"))
	c2 := NewFirewallChain("OUTPUT", "o", *outputRules, fw.prepareChainName("OUTPUT"))
	c3 := NewFirewallChain("FORWARD", "i", *forwardRules, fw.prepareChainName("FORWARD"))
	chains := [numberOfDefaultChains]FirewallChain{*c1, *c2, *c3}
	fw.chains = chains
	return nil
}

// isChainExist verifies if given iptables chain exists.
// Returns true chain exists.
func (fw *Firewall) isChainExist(chain int) bool {
	cmd := "/sbin/iptables"
	args := []string{"-L", fw.chains[chain].chainName}
	_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
	if err != nil {
		return false
	}
	return true
}

// detectMissingChains checks which Firewall chains haven't been created yet.
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
// pani-T0S0-OUTPUT, pani-T0S0-FORWARD, pani-T0S0-INPUT.
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

// DiverTrafficToPaniIptablesChain injects iptables rules to send traffic into the PANI chain.
func (fw *Firewall) DiverTrafficToPaniIptablesChain(chain int) error {
	// Should be like that
	// iptables -A INPUT -i tap1234 -j PANI-T0S1-INPUT
	log.Print("Diverting traffic in", chain)
	baseChain := fw.chains[chain].baseChain
	direction := fmt.Sprintf("-%s", fw.chains[chain].direction)
	chainName := fw.chains[chain].chainName
	cmd := "/sbin/iptables"
	args := []string{"-A", baseChain, direction, fw.interfaceName, "-j", chainName}
	_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
	if err != nil {
		log.Print("Diverting traffic failed", chain)
		return err
	}
	log.Print("Diverting traffic success", chain)
	return nil
}

// CreateRules creates permissive iptables rules for the given PANI chain
// to allow a traffic to flow between the Host and Endpoint.
func (fw *Firewall) CreateRules(chain int) error {
	log.Print("Creating firewall rules for chain", chain)
	for rule := range fw.chains[chain].rules {
		chainName := fw.chains[chain].chainName
		cmd := "/sbin/iptables"
		args := []string{"-A", chainName}
		args = append(args, strings.Split(fw.chains[chain].rules[rule], " ")...)
		args = append(args, []string{"-j", "ACCEPT"}...)
		_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
		if err != nil {
			return err
			log.Print("Creating firewall rules failed")
		}
	}
	log.Print("Creating firewall rules success")
	return nil
}

// CreateU32Rules creates wildcard iptables rules for the given PANI chain.
// These rules serve to restrict traffic between segments and tenants.
func (fw *Firewall) CreateU32Rules(chain int) error {
	log.Print("Creating U32 firewall rules for chain", chain)
	chainName := fw.chains[chain].chainName
	cmd := "/sbin/iptables"
	args := []string{"-A", chainName, "-m", "u32", "--u32", fw.u32Filter, "-j", "ACCEPT"}
	_, err := fw.Agent.Helper.Executor.Exec(cmd, args)
	if err != nil {
		return err
		log.Print("Creating U32 firewall rules failed")
	}
	log.Print("Creating U32 firewall rules failed for chain", chain)
	return nil
}

// prepareTenantSegmentMask returns integer representation of a netmask
// for tenant+segment bits in pseudo network.
func (fw *Firewall) prepareTenantSegmentMask() uint64 {
	var res uint64
	tenantBits := fw.Agent.config.TenantBits()
	segmentBits := fw.Agent.config.SegmentBits()
	combinedTSBits := tenantBits + segmentBits
	endpointBits := fw.Agent.config.EndpointBits()
	res = ((1 << combinedTSBits) - 1) << endpointBits
	return res
}

// ipToInt transforms IP address from net.IP form to integer form.
// Stolen from IPAM/config, should really be in some shared library.
func ipToInt(ip net.IP) uint64 {
	return uint64(ip[12])<<24 | uint64(ip[13])<<16 | uint64(ip[14])<<8 | uint64(ip[15])
}

// PseudoNetNetmaskInt returns integer representation of pseudo net netmask.
func (fw *Firewall) PseudoNetNetmaskInt() (uint64, error) {
	cidr, err := fw.Agent.config.PNetCIDR()
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
// This rules implemet PANI tenant/segment filtering
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
//      chainPrefix = 'pani-T0S1-'
//
//   Also return the chain-prefix we'll use for this interface. This is
//   typically a string such as:
//       pani-T<tenant-id>S<segment-id>-
//   For example, with tenant 1 and segment 2, this would be:
//       pani-T1S2-
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
	chainPrefix := fmt.Sprintf("pani-T%dS%d-", tenantID, segmentID)
	return filter, chainPrefix, nil
}

// prepareNetmaskBits returns integer representation of pseudo network netmask.
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
	endpointBits := fw.Agent.config.EndpointBits()
	segmentBits := fw.Agent.config.SegmentBits()
	sid := (addr >> endpointBits) & ((1 << segmentBits) - 1)
	return sid
}

// extractTenantID extracts tenant id from given the ip address.
// This is possible because tenant id encoded in the ip address.
func (fw *Firewall) extractTenantID(addr uint64) uint64 {
	endpointBits := fw.Agent.config.EndpointBits()
	segmentBits := fw.Agent.config.SegmentBits()
	tenantBits := fw.Agent.config.TenantBits()
	tid := (addr >> (endpointBits + segmentBits)) & ((1 << tenantBits) - 1)
	return tid
}

// provisionFirewallRules orchestrates Firewall to satisfy request
// to provision new endpoint.
// Creates per-tenant, per-segment iptables chains, diverts
// all traffic to/from/through netif.name interface to a proper chains.
// Currently tested with pani ML2 driver.
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
		if err := fw.DiverTrafficToPaniIptablesChain(chain); err != nil {
			return err
		}
		if err := fw.CreateRules(chain); err != nil {
			return err
		}
		if err := fw.CreateU32Rules(chain); err != nil {
			return err
		}
	}
	return nil
}
