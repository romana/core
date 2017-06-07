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

package server

import (
	"encoding/json"
	"strconv"

	"github.com/debedb/core/common"
	"github.com/romana/core/common/api"
	log "github.com/romana/rlog"
)

const (
	ipamDataKey = "/ipam/data"
)

func (r *Romanad) initIPAM() error {
	r.ipamLocker, err = r.store.NewLocker("ipam")
	if err != nil {
		return err
	}

	r.ipamLocker.Lock()
	defer r.ipamLocker.Unlock()

	// Check if IPAM info exists in the store
	ipamExists, err := r.store.Exists(r.store.Config.Prefix + ipamDataKey)
	if err != nil {
		return err
	}
	if ipamExists {
		// Load if exists
		log.Infof("Loading IPAM data from %s", ipamDataKey)
		kv, err := r.store.Get(ipamDataKey)
		if err != nil {
			return err
		}

		ipam, err = ParseIPAM(string(kv.Value), r.save, r.ipamLocker)
		if err != nil {
			return err
		}
	} else {
		// If does not exist, initialize and save
		log.Infof("No IPAM data found at %s, initializing", key)
		ipam, err = NewIPAM(r.save, r.ipamLocker)
		if err != nil {
			return err
		}
		err = r.save(ipam)
		if err != nil {
			return err
		}
	}

	return nil
}

// save implements the Saver interface of IPAM.
func (r *Romanad) save(ipam *IPAM) error {
	b, err := json.Marshal(ipam)
	if err != nil {
		return err
	}
	err = r.store.Put(ipamDataKey, b, nil)
	if err != nil {
		return err
	}
	return nil
}

// listHosts returns all hosts.
func (r *Romanad) listHosts(input interface{}, ctx common.RestContext) (interface{}, error) {
	return ipam.listHosts(), nil
}

// listBlocks returns api.IPAMBlocksResponse containing blocks in the given network.
// The network is specified with the "network" query parameter.
func (r *Romanad) listBlocks(input interface{}, ctx common.RestContext) (interface{}, error) {
	netName := ctx.PathVariables["network"]
	if network, ok := ipam.Networks[netName]; ok {
		resp := api.IPAMBlocksResponse{
			Revision: network.Revison,
			Blocks:   network.HostsGroups.getBlocksResponse(),
		}
		return resp, nil
	} else {
		return nil, common.NewError404("network", netName)
	}
}

func (r *Romanad) listAddresses(input interface{}, ctx common.RestContext) (interface{}, error) {
	netName := ctx.PathVariables["network"]
	blockID, err := strconv.Atoi(ctx.PathVariables["block"])
	addresses := make([]string, 0)
	if err != nil {
		return nil, err
	}
	if network, ok := ipam.Networks[netName]; ok {
		blocks := network.HostsGroups.listBlocks()

		for i, block := range blocks {
			if i == blockID {
				blockAddresses := block.listAddresses()
				addresses = append(addresses, blockAddresses...)
			}
		}
		return addresses, nil
	}
	return nil, common.NewError404("network", netName)
}

func (r *Romanad) listNetworks(input interface{}, ctx common.RestContext) (interface{}, error) {
	resp := make([]api.IPAMNetworkResponse, 0)
	for _, network := range ipam.Networks {
		n := api.IPAMNetworkResponse{
			CIDR:     api.IPNet{IPNet: *network.CIDR.IPNet},
			Name:     network.Name,
			Revision: network.Revison,
		}
		resp = append(resp, n)
	}
	return resp, nil
}

// deallocateIP deallocates IP specified by query parameter
// "addressName".
func (r *Romanad) deallocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	addressName := ctx.QueryVariables.Get("addressName")
	return nil, ipam.DeallocateIP(addressName)
}

func (r *Romanad) allocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	req := input.(api.IPAMAddressRequest)
	return ipam.AllocateIP(req.Name, req.Host, req.Tenant, req.Segment)
}

// updateTopology serves to update topology information in the Romana service
// as
func (r *Romanad) updateTopology(input interface{}, ctx common.RestContext) (interface{}, error) {
	topoReq := input.(api.TopologyUpdateRequest)
	return nil, ipam.updateTopology(topoReq)
}
