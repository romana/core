// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

import (
	"errors"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"log"
	"net"
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
		common.Route{
			"GET",
			"/allocateIpByName",
			ipam.legacyAllocateIpByName,
			nil,
		},
	}
	return routes
}

// handleHost handles request for a specific host's info
func (ipam *IPAMSvc) legacyAllocateIpByName(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Printf("LEgacy 1\n")
	tenantName := ctx.QueryVariables["tenantName"][0]
	segmentName := ctx.QueryVariables["segmentName"][0]
	hostName := ctx.QueryVariables["hostName"][0]
	names := ctx.QueryVariables["instanceName"]
	name := "VM"
	if len(names) > 0 {
		name = names[0]
	}
	log.Printf("LEgacy 2\n")
	vm := Vm{}
	vm.Name = name
	// Get host info from topology service
	topoUrl, err := common.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "topology")
	if err != nil {
		return nil, err
	}

	client, err := common.NewRestClient(topoUrl)
	if err != nil {
		return nil, err
	}
	log.Printf("LEgacy 3\n")
	index := common.IndexResponse{}
	err = client.Get(topoUrl, &index)
	if err != nil {
		return nil, err
	}

	hostsUrl := index.Links.FindByRel("host-list")
	var hosts []common.HostMessage

	err = client.Get(hostsUrl, &hosts)
	if err != nil {
		return nil, err
	}

	found := false
	for i := range hosts {
		if hosts[i].Name == hostName {
			found = true
			vm.HostId = hosts[i].Id
			break
		}
	}
	if !found {
		return nil, errors.New("Host with name " + hostName + " not found")
	}
	log.Printf("Host name %s has ID %s", hostName, vm.HostId)

	tenantSvcUrl, err := common.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "tenant")
	if err != nil {
		return nil, err
	}

	// TODO follow links once tenant service supports it. For now...

	tenantsUrl := fmt.Sprintf("%s/tenants", tenantSvcUrl)
	var tenants []tenant.Tenant
	err = client.Get(tenantsUrl, &tenants)
	if err != nil {
		return nil, err
	}
	found = false
	for i := range tenants {
		if tenants[i].Name == tenantName {
			found = true
			vm.TenantId = tenants[i].Id
			break
		}
	}
	if !found {
		return nil, errors.New("Tenant with name " + tenantName + " not found")
	}
	log.Printf("Tenant name %s has ID %s", tenantName, vm.TenantId)

	segmentsUrl := fmt.Sprintf("/tenants/%d/segments", vm.TenantId)
	var segments []tenant.Segment
	err = client.Get(segmentsUrl, &segments)
	if err != nil {
		return nil, err
	}
	found = false
	for i := range segments {
		if segments[i].Name == segmentName {
			found = true
			vm.SegmentId = segments[i].Id
			break
		}
	}
	if !found {
		return nil, errors.New("Segment with name " + hostName + " not found")
	}
	log.Printf("Sement name %s has ID %s", segmentName, vm.SegmentId)

	return ipam.addVm(&vm, ctx)
}

// handleHost handles request for a specific host's info
func (ipam *IPAMSvc) addVm(input interface{}, ctx common.RestContext) (interface{}, error) {
	vm := input.(*Vm)
	err := ipam.store.addVm(ipam.dc.EndpointSpaceBits, vm)
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

	hostInfoUrl := fmt.Sprintf("%s/%s", hostsUrl, vm.HostId)

	err = client.Get(hostInfoUrl, &host)

	if err != nil {
		return nil, err
	}

	tenantUrl, err := common.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "tenant")
	if err != nil {
		return nil, err
	}

	// TODO follow links once tenant service supports it. For now...

	t := &tenant.Tenant{}
	tenantsUrl := fmt.Sprintf("%s/tenants/%d", tenantUrl, vm.TenantId)

	err = client.Get(tenantsUrl, t)
	if err != nil {
		return nil, err
	}
	segmentUrl := fmt.Sprintf("/tenants/%d/segments/%d", vm.TenantId, vm.SegmentId)

	segment := &tenant.Segment{}
	err = client.Get(segmentUrl, segment)
	if err != nil {
		return nil, err
	}

	log.Printf("Constructing IP from Host IP %s, Tenant %d, Segment %d", host.RomanaIp, t.Seq, segment.Seq)

	vmBits := 32 - ipam.dc.PrefixBits - ipam.dc.PortBits - ipam.dc.TenantBits - ipam.dc.SegmentBits - ipam.dc.EndpointSpaceBits
	segmentBitShift := vmBits
	prefixBitShift := 32 - ipam.dc.PrefixBits
	tenantBitShift := segmentBitShift + ipam.dc.SegmentBits
	//	hostBitShift := tenantBitShift + ipam.dc.TenantBits

	hostIp, _, err := net.ParseCIDR(host.RomanaIp)
	if err != nil {
		return nil, err
	}
	hostIpInt := common.IPv4ToInt(hostIp)
	vmIpInt := (ipam.dc.Prefix << prefixBitShift) | hostIpInt | (t.Seq << tenantBitShift) | (segment.Seq << segmentBitShift) | vm.EffectiveSeq
	vmIpIp := common.IntToIPv4(vmIpInt)
	log.Printf("Constructing (%d << %d) | %d | (%d << %d) | ( %d << %d ) | %d=%s\n", ipam.dc.Prefix, prefixBitShift, hostIpInt, t.Seq, tenantBitShift, segment.Seq, segmentBitShift, vm.EffectiveSeq, vmIpIp.String())

	vm.Ip = vmIpIp.String()

	return vm, nil

}

// Name provides name of this service.
func (ipam *IPAMSvc) Name() string {
	return "ipam"
}

// Backing store
type ipamStore interface {
	validateConnectionInformation() error
	connect() error
	createSchema(overwrite bool) error
	setConfig(config map[string]interface{}) error
	// TODO use ptr
	addVm(stride uint, vm *Vm) error
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
	log.Printf("IPAM port: %s", config.Common.Api.Port)
	return ipam.store.setConfig(storeConfig)
}

func (ipam *IPAMSvc) createSchema(overwrite bool) error {
	return ipam.store.createSchema(overwrite)
}

// Runs IPAM service
func Run(rootServiceUrl string) (chan common.ServiceMessage, error) {
	ipam := &IPAMSvc{}
	config, err := common.GetServiceConfig(rootServiceUrl, ipam)
	if err != nil {
		return nil, err
	}
	ch, err := common.InitializeService(ipam, *config)
	return ch, err
}

func (ipam *IPAMSvc) Initialize() error {

	log.Println("Entering ipam.Initialize()")
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
	log.Printf("IPAM received datacenter information from topology service: %s\n", dc)
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
	config, err := common.GetServiceConfig(rootServiceUrl, ipamSvc)
	if err != nil {
		return err
	}

	err = ipamSvc.SetConfig(*config)
	if err != nil {
		return err
	}
	return ipamSvc.store.createSchema(overwrite)
}
