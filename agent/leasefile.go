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

type leaseOp int

const (
	leaseAdd leaseOp = iota
	leaseRemove
)

func (l leaseOp) String() string {
	var res string
	switch l {
	case leaseAdd:
		res = fmt.Sprintf("Add DHCP lease to a leasefile")
	case leaseRemove:
		res = fmt.Sprintf("Remove DHCP lease to a leasefile")
	}

	return res
}

// provisionLease adds a lease to leasefile
// and notifies DHCP server if file has changed.
func (l LeaseFile) provisionLease(netif *NetIf, op leaseOp) error {
	lease := fmt.Sprintf("%s %s", netif.Mac, netif.IP)
	// thread safety is responsibility of underlaying ensureLine method
	if err := l.Agent.Helper.ensureLine(l.Path, lease, op); err != nil {
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
