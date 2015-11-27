// Copyright (c) 2015 Pani Networks
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

package ipam

import (
	"errors"
	"net"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"log"
	"strings"
)

// IPAM service
type IPAMSvc struct {
	config common.ServiceConfig
	store  ipamStore
	dc     common.Datacenter
}

const (
	infoListPath = "/info"
)

// Provides Routes
func (ipam *IPAMSvc) Routes() common.Routes {

	routes := common.Routes{
		common.Route{
			"POST",
			"/vms",
			ipam.addVm,
			func() interface{} {
				return &Vm{}
			},
		},
	}
	return routes
}

type IpamResponse struct {
	Ip string
}


// handleHost handles request for a specific host's info
func (ipam *IPAMSvc) addVm(input interface{}, ctx common.RestContext) (interface{}, error) {
	vm := input.(Vm)
	vm, err := ipam.store.addVm(vm)
	if err != nil {
		return nil, err
	}

	// Get host info from topology service
	topoUrl, err := common.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "topology")
	if err != nil {
		return nil, err
	}
	client, err := common.NewRestClient(topoUrl)
	if err != nil {
		return nil, err
	}
	index := common.IndexResponse{}
	err = client.Get(topoUrl, &index)
	if err != nil {
		return nil, err
	}
	hostsUrl := index.Links.FindByRel("host-list")
	host := common.HostMessage{}
	err = client.Get(fmt.Sprintf("%s/%d", hostsUrl, vm.HostId), &host)
	if err != nil {
		return nil, err
	}

	tenantUrl, err := common.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "tenant")
	if err != nil {
		return nil, err
	}

	// TODO follow links once tenant service supports it. For now...

	t := &tenant.Tenant{}
	err = client.Get(fmt.Sprintf("%s/tenants/%d", tenantUrl, vm.TenantId), t)
	if err != nil {
		return nil, err
	}

	segment := &tenant.Segment{}
	err = client.Get(fmt.Sprintf("%s/segments/%d", tenantUrl, vm.SegmentId), segment)
	if err != nil {
		return nil, err
	}

	log.Printf("Constructing IP from Host IP %s, Tenant %d, Segment %d", host.RomanaIp, t.Seq, segment.Seq)

	
	vmBits := 32 - ipam.dc.PrefixBits - ipam.dc.PortBits - ipam.dc.TenantBits - ipam.dc.SegmentBits
	segmentBitShift := vmBits
	prefixBitShift := 32 - ipam.dc.PrefixBits
	tenantBitShift := segmentBitShift + ipam.dc.SegmentBits
//	hostBitShift := tenantBitShift + ipam.dc.TenantBits
	
	hostIp, _, err := net.ParseCIDR(host.RomanaIp)
	if err != nil {
		return nil, err	
	}
	hostIpInt := common.IPv4ToInt(hostIp)
	vmIpInt := (ipam.dc.Prefix << prefixBitShift) | hostIpInt | (t.Seq << tenantBitShift) | (segment.Seq << segmentBitShift) | vm.Seq
	vmIpIp := common.IntToIPv4(vmIpInt)
	return IpamResponse{Ip: vmIpIp.String()}, nil

}

// Backing store
type ipamStore interface {
	validateConnectionInformation() error
	connect() error
	createSchema(overwrite bool) error
	setConfig(config map[string]interface{}) error
	// TODO use ptr
	addVm(vm Vm) (Vm, error)
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (ipam *IPAMSvc) SetConfig(config common.ServiceConfig) error {
	// TODO this is a copy-paste of topology service, to refactor
	log.Println(config)
	ipam.config = config
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	storeType := strings.ToLower(storeConfig["type"].(string))
	switch storeType {
	case "mysql":
		ipam.store = &mysqlStore{}

		//	case "mock":
		//		ipam.store = &mockStore{}

	default:
		return errors.New("Unknown store type: " + storeType)
	}
	return ipam.store.setConfig(storeConfig)
}

func (ipam *IPAMSvc) createSchema(overwrite bool) error {
	return ipam.store.createSchema(overwrite)
}

// Runs IPAM service
func Run(rootServiceUrl string) (chan common.ServiceMessage, error) {
	ipam := &IPAMSvc{}
	config, err := common.GetServiceConfig(rootServiceUrl, "topology")
	if err != nil {
		return nil, err
	}
	ch, err := common.InitializeService(ipam, *config)
	return ch, err
}

func (ipam *IPAMSvc) Initialize() error {
	err := ipam.store.connect()
	if err != nil {
		return err
	}

	topologyURL, err := common.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "topology")
	if err != nil {
		return err
	}

	client, err := common.NewRestClient(topologyURL)
	if err != nil {
		return err
	}
	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return err
	}

	dcURL := index.Links.FindByRel("datacenter")
	dc := common.Datacenter{}
	err = client.Get(dcURL, &dc)
	if err != nil {
		return err
	}
	// TODO should this always be queried?
	ipam.dc = dc
	return nil
}

// Runs topology service
func CreateSchema(rootServiceUrl string, overwrite bool) error {
	log.Println("In CreateSchema(", rootServiceUrl, ",", overwrite, ")")
	ipamSvc := &IPAMSvc{}
	config, err := common.GetServiceConfig(rootServiceUrl, "ipam")
	if err != nil {
		return err
	}

	err = ipamSvc.SetConfig(*config)
	if err != nil {
		return err
	}
	return ipamSvc.store.createSchema(overwrite)
}
