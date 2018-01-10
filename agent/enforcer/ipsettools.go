// Copyright (c) 2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Policy enforcer package translates romana policies into iptables rules.
package enforcer

import (
	"context"
	"time"

	"github.com/romana/ipset"
)

// updateIpsets is a flush/rebuild implementation of ipset update
// it will wipe all sets in a system and populate new ones.
// TODO for Stas this monopolizes ipsets
// and also pollutes with sets which never deleted.
// Need cleaner implementation
func updateIpsets(ctx context.Context, sets *ipset.Ipset) error {

	err := attemptIpsetCleanup(ctx, sets)
	if err != nil {
		return err
	}

	ipsetHandle, err := ipset.NewHandle()
	if err != nil {
		return err
	}

	err = ipsetHandle.Start()
	if err != nil {
		return err
	}

	err = ipsetHandle.Create(sets)
	if err != nil {
		return err
	}

	err = ipsetHandle.Add(sets)
	if err != nil {
		return err
	}

	err = ipsetHandle.Quit()
	if err != nil {
		return err
	}

	cTimout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = ipsetHandle.Wait(cTimout)
	if err != nil {
		return err
	}

	return nil

}

// attemptIpsetCleanup attempts to destroy every set.
// TODO make it less nuclear.
func attemptIpsetCleanup(ctx context.Context, sets *ipset.Ipset) error {
	iset, _ := ipset.Load(ctx)
	for _, set := range iset.Sets {
		_, _ = ipset.Destroy(set)
	}

	// flush everything that survived mass destroy.
	_, err := ipset.Flush(nil)

	return err
}
