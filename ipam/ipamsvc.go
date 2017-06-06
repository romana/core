// Copyright (c) 2016-2017 Pani Networks
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

package ipam

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	libkvStore "github.com/docker/libkv/store"

	"github.com/romana/core/common"
	"github.com/romana/core/common/store"
	"github.com/romana/core/pkg/api"
	log "github.com/romana/rlog"
)

// IPAMSvc provides REST services for IPAM functionality.
type IPAMSvc struct {
	client *common.RestClient
	config common.ServiceConfig
	store  *store.KvStore
	locker libkvStore.Locker
	routes common.Route
}

// Name provides name of this service.
func (ipam *IPAMSvc) Name() string {
	return "ipam"
}

// Returns an error if cannot connect to the data store, or, if applicable,
// if ChunkIPAM cannot be initialized.
func (svc *IPAMSvc) SetConfig(config common.ServiceConfig) error {
	// TODO this is a copy-paste of topology service, to refactor
	var err error
	svc.config = config
	storeConfigMap := config.ServiceSpecific["store"].(map[string]interface{})
	storeConfig, err := common.MakeStoreConfig(storeConfigMap)
	if err != nil {
		return err
	}
	if storeConfig.Type != common.StoreTypeEtcd {
		return errors.New("Only etcd store is supported")
	}
	kvStore, err := store.GetStore(storeConfigMap)
	if err != nil {
		return err
	}
	svc.store = kvStore.(*store.KvStore)
	return nil
}

func (svc *IPAMSvc) CreateSchema(overwrite bool) error {
	return svc.store.CreateSchema(overwrite)
}

// save implements the Saver interface of IPAM.
func (svc *IPAMSvc) save(ipam *IPAM) error {
	b, err := json.Marshal(ipam)
	if err != nil {
		return err
	}
	err = svc.store.Db.Put(svc.store.Db.Prefix+"/ipam/data", b, nil)
	if err != nil {
		return err
	}
	return nil
}

// Lock implements Lock method of sync.Locker interface.
func (svc *IPAMSvc) Lock() {
	// TODO do we need these channels?
	stopChan := make(chan struct{})
	for {
		_, err := svc.locker.Lock(stopChan)
		if err == nil {
			return
		}
		log.Errorf("Error attempting to acquire lock: %s", err)
		time.Sleep(100 * time.Millisecond)
	}
}

// Unlock implements Unlock method of sync.Locker interface.
func (svc *IPAMSvc) Unlock() {
	err := svc.locker.Unlock()
	if err != nil {
		log.Error(err)
	}
}

// Initialize implements Initialize method of Service interface
func (svc *IPAMSvc) Initialize(client *common.RestClient) error {
	var err error
	log.Debug("Entering ipam.Initialize()")
	err = svc.store.Connect()
	if err != nil {
		return err
	}

	svc.locker, err = svc.store.Db.NewLock(svc.store.Db.Prefix+"/ipam/lock", nil)
	svc.Lock()
	defer svc.Unlock()

	key := svc.store.Db.Prefix + "/ipam/data"

	// Check if IPAM info exists in the store
	ipamExists, err := svc.store.Db.Exists(key)
	if err != nil {
		return err
	}
	if ipamExists {
		// Load if exists
		log.Infof("Loading IPAM data from %s", key)
		kv, err := svc.store.Db.Get(key)
		if err != nil {
			return err
		}

		ipam, err = ParseIPAM(string(kv.Value), svc.save, svc)
		if err != nil {
			return err
		}
	} else {
		// If does not exist, initialize and save
		log.Infof("No IPAM data found at %s, initializing", key)
		ipam, err = NewIPAM(svc.save, svc)
		if err != nil {
			return err
		}
		err = svc.save(ipam)
		if err != nil {
			return err
		}
	}

	svc.client = client
	return nil
}

// Routes provided by ipam.
func (svc *IPAMSvc) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:  "GET",
			Pattern: "/networks/{network}/blocks/",
			Handler: svc.listBlocks,
		},
		common.Route{
			Method:      "POST",
			Pattern:     "/address",
			Handler:     svc.allocateIP,
			MakeMessage: func() interface{} { return &api.IPAMAddressRequest{} },
		},
		common.Route{
			Method:  "DELETE",
			Pattern: "/address",
			Handler: svc.deallocateIP,
		},
		common.Route{
			Method:  "GET",
			Pattern: "/networks",
			Handler: svc.listNetworks,
		},

		common.Route{
			Method:      "POST",
			Pattern:     "/topology",
			Handler:     svc.updateTopology,
			MakeMessage: func() interface{} { return &api.TopologyUpdateRequest{} },
		},
	}
	return routes
}

// listBlocks returns api.IPAMBlocksResponse containing blocks in the given network.
// The network is specified with the "network" query parameter.
func (svc *IPAMSvc) listBlocks(input interface{}, ctx common.RestContext) (interface{}, error) {
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

func (svc *IPAMSvc) listAddresses(input interface{}, ctx common.RestContext) (interface{}, error) {
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

func (svc *IPAMSvc) listNetworks(input interface{}, ctx common.RestContext) (interface{}, error) {
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
func (svc *IPAMSvc) deallocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	addressName := ctx.QueryVariables.Get("addressName")
	return nil, ipam.DeallocateIP(addressName)
}

func (svc *IPAMSvc) allocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	req := input.(api.IPAMAddressRequest)
	return ipam.AllocateIP(req.Name, req.Host, req.Tenant, req.Segment)
}

// updateTopology serves to update topology information in the Romana service
// as
func (svc *IPAMSvc) updateTopology(input interface{}, ctx common.RestContext) (interface{}, error) {
	topoReq := input.(api.TopologyUpdateRequest)
	return nil, ipam.updateTopology(topoReq)
}
