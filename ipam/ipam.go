// Copyright (c) 2016 Pani Networks
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
)

// IPAM provides ipam service.
type IPAM struct {
	config common.ServiceConfig
	store  ipamStore
	dc     common.Datacenter
}

const (
	infoListPath = "/info"
)

// Routes provided by ipam.
func (ipam *IPAM) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:          "POST",
			Pattern:         "/endpoints",
			Handler:         ipam.addEndpoint,
			MakeMessage:     func() interface{} { return &Endpoint{} },
			UseRequestToken: true,
		},
		common.Route{
			Method:          "DELETE",
			Pattern:         "/endpoints/{ip}",
			Handler:         ipam.deleteEndpoint,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         "/allocateIpByName",
			Handler:         ipam.legacyAllocateIpByName,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
	}
	return routes
}

// handleHost handles request for a specific host's info
func (ipam *IPAM) legacyAllocateIpByName(input interface{}, ctx common.RestContext) (interface{}, error) {
	tenantName := ctx.QueryVariables["tenantName"][0]
	segmentName := ctx.QueryVariables["segmentName"][0]
	hostName := ctx.QueryVariables["hostName"][0]
	names := ctx.QueryVariables["instanceName"]
	name := "Endpoint"
	if len(names) > 0 {
		name = names[0]
	}
	Endpoint := Endpoint{}
	Endpoint.Name = name

	client, err := common.NewRestClient(common.GetRestClientConfig(ipam.config))
	if err != nil {
		return nil, err
	}
	// Get host info from topology service
	topoUrl, err := client.GetServiceUrl("topology")
	if err != nil {
		return nil, err
	}

	index := common.IndexResponse{}
	err = client.Get(topoUrl, &index)
	if err != nil {
		return nil, err
	}

	hostsURL := index.Links.FindByRel("host-list")
	var hosts []common.HostMessage

	err = client.Get(hostsURL, &hosts)
	if err != nil {
		return nil, err
	}

	found := false
	for i := range hosts {
		if hosts[i].Name == hostName {
			found = true
			Endpoint.HostId = hosts[i].Id
			break
		}
	}
	if !found {
		msg := fmt.Sprintf("Host with name %s not found", hostName)
		log.Printf(msg)
		return nil, errors.New(msg)
	}
	log.Printf("Host name %s has ID %s", hostName, Endpoint.HostId)

	tenantSvcUrl, err := client.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "tenant")
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
	var i int
	for i = range tenants {
		if tenants[i].Name == tenantName {
			found = true
			Endpoint.TenantId = fmt.Sprintf("%d", tenants[i].ID)
			log.Printf("IPAM: Tenant name %s has ID %s, original %d\n", tenantName, Endpoint.TenantId, tenants[i].ID)
			break
		}
	}
	if !found {
		return nil, errors.New("Tenant with name " + tenantName + " not found")
	}
	log.Printf("IPAM: Tenant name %s has ID %s, original %d\n", tenantName, Endpoint.TenantId, tenants[i].ID)

	segmentsUrl := fmt.Sprintf("/tenants/%s/segments", Endpoint.TenantId)
	var segments []tenant.Segment
	err = client.Get(segmentsUrl, &segments)
	if err != nil {
		return nil, err
	}
	found = false
	for _, s := range segments {
		if s.Name == segmentName {
			found = true
			Endpoint.SegmentId = fmt.Sprintf("%d", s.Id)
			break
		}
	}
	if !found {
		return nil, errors.New("Segment with name " + hostName + " not found")
	}
	log.Printf("Segment name %s has ID %s", segmentName, Endpoint.SegmentId)
	return ipam.addEndpoint(&Endpoint, ctx)
}

// addEndpoint handles request to add an endpoint and
// allocate an IP address.
func (ipam *IPAM) addEndpoint(input interface{}, ctx common.RestContext) (interface{}, error) {
	Endpoint := input.(*Endpoint)
	client, err := common.NewRestClient(common.GetRestClientConfig(ipam.config))
	if err != nil {
		return nil, err
	}
	// Get host info from topology service
	topoUrl, err := client.GetServiceUrl("topology")
	if err != nil {
		return nil, err
	}

	index := common.IndexResponse{}
	err = client.Get(topoUrl, &index)
	if err != nil {
		return nil, err
	}

	hostsURL := index.Links.FindByRel("host-list")
	host := common.HostMessage{}

	hostInfoURL := fmt.Sprintf("%s/%s", hostsURL, Endpoint.HostId)
	err = client.Get(hostInfoURL, &host)

	if err != nil {
		return nil, err
	}

	tenantUrl, err := client.GetServiceUrl(ipam.config.Common.Api.RootServiceUrl, "tenant")
	if err != nil {
		return nil, err
	}

	// TODO follow links once tenant service supports it. For now...

	t := &tenant.Tenant{}
	tenantsUrl := fmt.Sprintf("%s/tenants/%s", tenantUrl, Endpoint.TenantId)
	log.Printf("IPAM calling %s\n", tenantsUrl)
	err = client.Get(tenantsUrl, t)
	if err != nil {
		return nil, err
	}
	log.Printf("IPAM received tenant %s ID %d, sequence %d\n", t.Name, t.ID, t.Seq)

	segmentUrl := fmt.Sprintf("/tenants/%s/segments/%s", Endpoint.TenantId, Endpoint.SegmentId)
	log.Printf("IPAM calling %s\n", segmentUrl)
	segment := &tenant.Segment{}
	err = client.Get(segmentUrl, segment)
	if err != nil {
		return nil, err
	}

	log.Printf("Constructing IP from Host IP %s, Tenant %d, Segment %d", host.RomanaIp, t.Seq, segment.Seq)

	EndpointBits := 32 - ipam.dc.PrefixBits - ipam.dc.PortBits - ipam.dc.TenantBits - ipam.dc.SegmentBits - ipam.dc.EndpointSpaceBits
	segmentBitShift := EndpointBits
	//	prefixBitShift := 32 - ipam.dc.PrefixBits
	tenantBitShift := segmentBitShift + ipam.dc.SegmentBits
	log.Printf("Parsing Romana IP address of host %s: %s\n", host.Name, host.RomanaIp)
	_, network, err := net.ParseCIDR(host.RomanaIp)
	if err != nil {
		return nil, err
	}
	hostIpInt := common.IPv4ToInt(network.IP)
	tSeq := t.Seq - 1
	sSeq := segment.Seq - 1
	upToEndpointIpInt := hostIpInt | (tSeq << tenantBitShift) | (sSeq << segmentBitShift)
	log.Printf("IPAM: before calling addEndpoint:  %v | (%v << %v) | (%v << %v): %v ", network.IP.String(), tSeq, tenantBitShift, sSeq, segmentBitShift, common.IntToIPv4(upToEndpointIpInt))
	err = ipam.store.addEndpoint(Endpoint, upToEndpointIpInt, ipam.dc.EndpointSpaceBits)
	if err != nil {
		return nil, err
	}
	return Endpoint, nil

}

// deleteEndpoint releases the IP(s) owned by the endpoint into assignable
// pool.
func (ipam *IPAM) deleteEndpoint(input interface{}, ctx common.RestContext) (interface{}, error) {
	return ipam.store.deleteEndpoint(ctx.PathVariables["ip"])
}

// Name provides name of this service.
func (ipam *IPAM) Name() string {
	return "ipam"
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (ipam *IPAM) SetConfig(config common.ServiceConfig) error {
	// TODO this is a copy-paste of topology service, to refactor
	log.Println(config)
	ipam.config = config
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	log.Printf("IPAM port: %d", config.Common.Api.Port)
	ipam.store = ipamStore{}
	ipam.store.ServiceStore = &ipam.store
	return ipam.store.SetConfig(storeConfig)

}

func (ipam *IPAM) createSchema(overwrite bool) error {
	return ipam.store.CreateSchema(overwrite)
}

// Run mainly runs IPAM service.
<<<<<<< HEAD
func Run(rootServiceUrl string) (*common.RestServiceInfo, error) {
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig())
	if err != nil {
		return nil, err
	}
	ipam := &IPAMSvc{}
	config, err := client.GetServiceConfig(ipam)
=======
func Run(rootServiceUrl string, cred *common.Credential) (*common.RestServiceInfo, error) {
	clientConfig := common.GetDefaultRestClientConfig()
	clientConfig.Credential = cred
	client, err := common.NewRestClient(rootServiceUrl, clientConfig)
	if err != nil {
		return nil, err
	}
	ipam := &IPAM{}
	config, err := client.GetServiceConfig(rootServiceUrl, ipam)
>>>>>>> master
	if err != nil {
		return nil, err
	}
	return common.InitializeService(ipam, *config)

}

// Initialize implements Initialize method of Service interface
func (ipam *IPAM) Initialize() error {
	log.Println("Entering ipam.Initialize()")
	err := ipam.store.Connect()
	if err != nil {
		return err
	}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig())
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl("topology")
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
	log.Printf("IPAM received datacenter information from topology service: %#v\n", dc)
	err = client.Get(dcURL, &dc)
	if err != nil {
		return err
	}
	// TODO should this always be queried?
	ipam.dc = dc
	return nil
}

// CreateSchema creates schema for IPAM service.
func CreateSchema(rootServiceUrl string, overwrite bool) error {
	log.Println("In CreateSchema(", rootServiceUrl, ",", overwrite, ")")
	IPAM := &IPAM{}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootServiceUrl))
	if err != nil {
		return err
	}
	config, err := client.GetServiceConfig(ipamSvc)
	if err != nil {
		return err
	}

	err = IPAM.SetConfig(*config)
	if err != nil {
		return err
	}
	return IPAM.store.CreateSchema(overwrite)
}
