package firewall

import (
	utilexec "github.com/romana/core/pkg/util/exec"
	"net"
)

type Firewall interface {
	// ProvisionEndpoint generates and applies rules for given endpoint.
	ProvisionEndpoint(netif FirewallEndpoint) error

	// EnsureRule checks if specified rule in desired state.
	EnsureRule(ruleSpec []string, op RuleState) error

	// ListRules returns a list of firewall rules.
	ListRules() ([]IPtablesRule, error)

	// Cleanup deletes DB records and uninstall rules associated with given endpoint.
	Cleanup(netif FirewallEndpoint) error
}

// NetConfig is for agent.NetworkConfig.
type NetConfig interface {
	PNetCIDR() (cidr *net.IPNet, err error)
	TenantBits() uint
	SegmentBits() uint
	EndpointBits() uint
	EndpointNetmaskSize() uint64
	RomanaGW() net.IP
}

// NewFirewall returns fully initialized firewall struct, with rules and chains
// configured for given endpoint.
func NewFirewall(executor utilexec.Executable, store FirewallStore, nc NetConfig, platform FirewallPlatform) (Firewall, error) {

	fwstore := firewallStore{}
	fwstore.DbStore = store.GetDb()
	fwstore.mu = store.GetMutex()

	fw := new(IPtables)
	fw.Store = fwstore
	fw.os = executor
	fw.Platform = platform
	fw.networkConfig = nc

	return *fw, nil
}

type FirewallPlatform int

const (
	KubernetesPlatform FirewallPlatform = iota
	OpenStackPlatform
)

func (fp FirewallPlatform) String() string {
	var result string
	switch fp {
	case KubernetesPlatform:
		return "Kubernetes"
	case OpenStackPlatform:
		return "OpenStack"
	}

	return result
}

// RuleState is a parameter for ensureIPtablesRule function
// which describes desired state of firewall rule.
type RuleState int

const (
	ensureLast RuleState = iota
	ensureFirst
	ensureAbsent
)

func (i RuleState) String() string {
	var result string
	switch i {
	case ensureLast:
		result = "Ensuring rule at the bottom"
	case ensureFirst:
		result = "Ensuring rule at the top"
	case ensureAbsent:
		result = "Ensuring rule is absent"
	}

	return result
}

// Interface for agent.NetIf.
type FirewallEndpoint interface {
	GetMac() string
	GetIP() net.IP
	GetName() string
}
