package agent

import (
	"fmt"
)

// LeaseFile is a structure that manages DHCP leases in file
// and notifyies DHCP server when leases are updated.
type LeaseFile struct {
	Path  string
	Agent *Agent
}

// NewLeaseFile returns fully initialized LeaseFile struct.
func NewLeaseFile(path string, agent *Agent) LeaseFile {
	lf := new(LeaseFile)
	lf.Path = path
	lf.Agent = agent
	return *lf
}

// provisionLease is a method that adds a lease to leasefile
// and notifies DHCP server if file has changed.
func (l LeaseFile) provisionLease(netif *NetIf) error {
	lease := fmt.Sprintf("%s %s", netif.mac, netif.ip)
	// thread safety is responsibility of underlaying ensureLine method
	if err := l.Agent.Helper.ensureLine(l.Path, lease); err != nil {
		return err
	}

	dhcpPid, err := l.Agent.Helper.DhcpPid()
	if err != nil {
		return err
	}
	if err := l.Agent.Helper.sendSighup(dhcpPid); err != nil {
		return err
	}
	return nil
}
