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
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

import (
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
			Pattern:         "/allocateIP",
			Handler:         ipam.allocateIP,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
	}
	return routes
}

// allocateIP finds internal Romana information based on tenantID/tenantName and other provided parameters, then adds
// that endpoint to IPAM, and passes through the allocated IP
func (ipam *IPAM) allocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	// TODO
	// This is the current state of calling this service from other environments:
	// 1. OpenStack (IPAM plugin driver):
	// https://github.com/romana/networking-romana/blob/stable/liberty/networking_romana/driver/ipam_romana.py#L120
	//
	// url = ("%s/allocateIP?tenantID=%s&segmentName=%s&hostName=%s" %
	//               (self.ipam_url, address_request.tenant_id,
	//                address_request.segment_id, address_request.host_id))
	// 2. Kubernetes (CNI Plugin)
	// https://github.com/romana/kube/blob/master/CNI/romana#L134
	// IP=$(curl -s "http://$ROMANA_MASTER_IP:9601/allocateIP?tenantName=${tenant}&segmentName=${segment}&hostName=${node}" | get_json_kv | get_ip)
	ten := &tenant.Tenant{}
	var findFlag common.FindFlag
	if tenantID := ctx.QueryVariables.Get("tenantID"); tenantID != "" {
		// This is how IPAM plugin driver calls us.
		ten.ExternalID = tenantID
		findFlag = common.FindExactlyOne
	} else if tenantName := ctx.QueryVariables.Get("tenantName"); tenantName != "" {
		// This is because CNI plugin right now calls us by name
		ten.Name = tenantName
		findFlag = common.FindLast
	} else {
		return nil, common.NewError400("Either tenantID or tenantName must be specified.")
	}

	segmentName := ctx.QueryVariables.Get("segmentName")
	if segmentName == "" {
		err := common.NewError400("Missing or empty segmentName parameter")
		log.Printf("IPAM encountered an error: %v", err)
		return nil, err
	}
	hostName := ctx.QueryVariables.Get("hostName")
	if hostName == "" {
		err := common.NewError400("Missing or empty hostName parameter")
		log.Printf("IPAM encountered an error: %v", err)
		return nil, err
	}

	endpoint := Endpoint{}
	instanceName := ctx.QueryVariables.Get("instanceName")
	if instanceName != "" {
		endpoint.Name = instanceName
	}

	client, err := common.NewRestClient(common.GetRestClientConfig(ipam.config))
	if err != nil {
		log.Printf("IPAM encountered an error: %v", err)
		return nil, err
	}

	host := &common.Host{}
	host.Name = hostName
	err = client.Find(host, common.FindExactlyOne)
	if err != nil {
		log.Printf("IPAM encountered an error finding host for name %s %v", hostName, err)
		return nil, err
	}
	endpoint.HostId = fmt.Sprintf("%d", host.ID)
	log.Printf("Host name %s has ID %s", hostName, endpoint.HostId)

	err = client.Find(ten, findFlag)
	if err != nil {
		log.Printf("IPAM encountered an error finding tenants %+v: %v", ten, err)
		return nil, err
	}
	endpoint.TenantID = fmt.Sprintf("%d", ten.ID)
	seg := &tenant.Segment{Name: segmentName, TenantID: ten.ID}
	err = client.Find(seg, findFlag)
	if err != nil {
		log.Printf("IPAM encountered an error finding segments: %+v: %v", seg, err)
		return nil, err
	}

	endpoint.SegmentID = fmt.Sprintf("%d", seg.ID)
	log.Printf("Segment name %s has ID %s", segmentName, endpoint.SegmentID)
	return ipam.addEndpoint(&endpoint, ctx)
}

// addEndpoint handles request to add an endpoint and
// allocate an IP address.
func (ipam *IPAM) addEndpoint(input interface{}, ctx common.RestContext) (interface{}, error) {
	endpoint := input.(*Endpoint)
	client, err := common.NewRestClient(common.GetRestClientConfig(ipam.config))
	if err != nil {
		log.Printf("IPAM encountered an error getting a REST client instance: %v", err)
		return nil, err
	}
	// Get host info from topology service
	topoUrl, err := client.GetServiceUrl("topology")
	if err != nil {
		log.Printf("IPAM encountered an error getting a topology service URL %v", err)
		return nil, err
	}

	index := common.IndexResponse{}
	err = client.Get(topoUrl, &index)
	if err != nil {
		log.Printf("IPAM encountered an error querying topology: %v", err)
		return nil, err
	}

	hostsURL := index.Links.FindByRel("host-list")
	host := common.Host{}

	hostInfoURL := fmt.Sprintf("%s/%s", hostsURL, endpoint.HostId)
	err = client.Get(hostInfoURL, &host)

	if err != nil {
		log.Printf("IPAM encountered an error querying topology for hosts: %v", err)
		return nil, err
	}

	tenantUrl, err := client.GetServiceUrl("tenant")
	if err != nil {
		log.Printf("IPAM encountered an error getting tenant srevice URL: %v", err)
		return nil, err
	}

	// TODO follow links once tenant service supports it. For now...

	t := &tenant.Tenant{}
	tenantsUrl := fmt.Sprintf("%s/tenants/%s", tenantUrl, endpoint.TenantID)
	log.Printf("IPAM calling %s\n", tenantsUrl)
	err = client.Get(tenantsUrl, t)
	if err != nil {
		log.Printf("IPAM encountered an error querying tenant service for tenant %s: %v", endpoint.TenantID, err)
		return nil, err
	}
	log.Printf("IPAM: received tenant %s ID %d, sequence %d\n", t.Name, t.ID, t.Seq)

	segmentUrl := fmt.Sprintf("/tenants/%s/segments/%s", endpoint.TenantID, endpoint.SegmentID)
	log.Printf("IPAM: calling %s\n", segmentUrl)
	segment := &tenant.Segment{}
	err = client.Get(segmentUrl, segment)
	if err != nil {
		log.Printf("IPAM encountered an error querying tenant service for tenant %s and segment %s: %v", endpoint.TenantID, endpoint.SegmentID, err)
		return nil, err
	}

	log.Printf("Constructing IP from Host IP %s, Tenant %d, Segment %d", host.RomanaIp, t.Seq, segment.Seq)

	endpointBits := 32 - ipam.dc.PrefixBits - ipam.dc.PortBits - ipam.dc.TenantBits - ipam.dc.SegmentBits - ipam.dc.EndpointSpaceBits
	segmentBitShift := endpointBits
	//	prefixBitShift := 32 - ipam.dc.PrefixBits
	tenantBitShift := segmentBitShift + ipam.dc.SegmentBits
	log.Printf("Parsing Romana IP address of host %s: %s\n", host.Name, host.RomanaIp)
	_, network, err := net.ParseCIDR(host.RomanaIp)
	if err != nil {
		log.Printf("IPAM encountered an error parsing %s: %v", host.RomanaIp, err)
		return nil, err
	}
	hostIpInt := common.IPv4ToInt(network.IP)
	upToEndpointIpInt := hostIpInt | (t.Seq << tenantBitShift) | (segment.Seq << segmentBitShift)
	log.Printf("IPAM: before calling addEndpoint:  %v | (%v << %v) | (%v << %v): %v ", network.IP.String(), t.Seq, tenantBitShift, segment.Seq, segmentBitShift, common.IntToIPv4(upToEndpointIpInt))
	err = ipam.store.addEndpoint(endpoint, upToEndpointIpInt, ipam.dc.EndpointSpaceBits)
	if err != nil {
		log.Printf("IPAM encountered an error adding endpoint to db: %v", err)
		return nil, err
	}
	return endpoint, nil

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
func Run(rootServiceUrl string, cred *common.Credential) (*common.RestServiceInfo, error) {
	clientConfig := common.GetDefaultRestClientConfig(rootServiceUrl)
	clientConfig.Credential = cred
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		return nil, err
	}
	ipam := &IPAM{}
	config, err := client.GetServiceConfig(ipam.Name())
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
	client, err := common.NewRestClient(common.GetRestClientConfig(ipam.config))
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
	log.Printf("IPAM received datacenter information from topology service: %+v\n", dc)
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
	ipam := &IPAM{}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootServiceUrl))
	if err != nil {
		return err
	}
	config, err := client.GetServiceConfig(ipam.Name())
	if err != nil {
		return err
	}

	err = ipam.SetConfig(*config)
	if err != nil {
		return err
	}
	return ipam.store.CreateSchema(overwrite)
}
