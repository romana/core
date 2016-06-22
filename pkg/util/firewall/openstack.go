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
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
//
// OpenStack specific code for iptables implementation of firewall.

package firewall

import (
	"github.com/golang/glog"
)

// provisionIPtablesRules orchestrates IPtables to satisfy request
// to provision new endpoint.
// Creates per-tenant, per-segment iptables chains, diverts
// all traffic to/from/through netif.name interface to a proper chains.
// Currently tested with Romana ML2 driver.
func (fw *IPtables) provisionIPtablesRules() error {
	missingChains := fw.detectMissingChains()
	glog.Info("Firewall: creating chains")
	err := fw.CreateChains(missingChains)
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

	for _, chain := range fw.chains {
		if err := fw.DivertTrafficToRomanaIPtablesChain(chain, installDivertRules); err != nil {
			return err
		}
	}

	return nil
}
