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
	"database/sql"
	"fmt"
	"net"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/core/common/store"

	log "github.com/romana/rlog"
)

// IPAM provides ipam service.
type IPAM struct {
	client *common.RestClient
	config common.ServiceConfig
	store  ipamStore
	dc     common.Datacenter
	sync.RWMutex
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
			MakeMessage:     func() interface{} { return &common.IPAMEndpoint{} },
			UseRequestToken: true,
		},
		common.Route{
			Method:          "GET",
			Pattern:         "/endpoints",
			Handler:         ipam.listEndpoints,
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
			UseRequestToken: true,
		},
	}
	return routes
}

// allocateIP finds internal Romana information based on tenantID/tenantName and other provided parameters, then adds
// that IPAMEndpoint to IPAM, and passes through the allocated IP
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

	ipam.RLock()

	ten := &common.Tenant{}
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
		ipam.RUnlock()
		return nil, common.NewError400("Either tenantID or tenantName must be specified.")
	}

	segmentName := ctx.QueryVariables.Get("segmentName")
	if segmentName == "" {
		err := common.NewError400("Missing or empty segmentName parameter")
		log.Printf("IPAM encountered an error: %v", err)
		ipam.RUnlock()
		return nil, err
	}
	hostName := ctx.QueryVariables.Get("hostName")
	if hostName == "" {
		err := common.NewError400("Missing or empty hostName parameter")
		log.Printf("IPAM encountered an error: %v", err)
		ipam.RUnlock()
		return nil, err
	}

	endpoint := common.IPAMEndpoint{}
	instanceName := ctx.QueryVariables.Get("instanceName")
	if instanceName != "" {
		endpoint.Name = instanceName
	}

	host := &common.Host{}
	host.Name = hostName
	var err error
	err = ipam.client.Find(host, common.FindLast)
	if err != nil {
		log.Printf("IPAM encountered an error finding host for name %s %v", hostName, err)
		ipam.RUnlock()
		return nil, err
	}
	endpoint.HostId = fmt.Sprintf("%d", host.ID)
	log.Printf("Host name %s has ID %s", hostName, endpoint.HostId)

	err = ipam.client.Find(ten, findFlag)
	if err != nil {
		log.Printf("IPAM encountered an error finding tenants %+v: %v", ten, err)
		ipam.RUnlock()
		return nil, err
	}
	endpoint.TenantID = fmt.Sprintf("%d", ten.ID)
	seg := &common.Segment{Name: segmentName, TenantID: ten.ID}
	err = ipam.client.Find(seg, findFlag)
	if err != nil {
		log.Printf("IPAM encountered an error finding segments: %+v: %v", seg, err)
		ipam.RUnlock()
		return nil, err
	}

	endpoint.SegmentID = fmt.Sprintf("%d", seg.ID)
	log.Printf("Segment name %s has ID %s", segmentName, endpoint.SegmentID)
	token := ctx.QueryVariables.Get(common.RequestTokenQueryParameter)
	if token != "" {
		endpoint.RequestToken = sql.NullString{Valid: true, String: token}
	}

	ipam.RUnlock()

	return ipam.addEndpoint(&endpoint, ctx)
}

// addIPAMEndpoint handles request to add an IPAMEndpoint and
// allocate an IP address.
func (ipam *IPAM) addEndpoint(input interface{}, ctx common.RestContext) (interface{}, error) {
	ipam.Lock()
	defer ipam.Unlock()

	endpoint := input.(*common.IPAMEndpoint)
	log.Debugf("IPAM: Attempting to allocate IP for %s", endpoint.Name)
	// Get host info from topology service
	topoUrl, err := ipam.client.GetServiceUrl("topology")
	if err != nil {
		log.Errorf("IPAM: Encountered an error getting a topology service URL %v", err)
		return nil, err
	}

	index := common.IndexResponse{}
	err = ipam.client.Get(topoUrl, &index)
	if err != nil {
		log.Errorf("IPAM: Encountered an error querying topology: %v", err)
		return nil, err
	}

	hostsURL := index.Links.FindByRel("host-list")
	host := common.Host{}

	hostInfoURL := fmt.Sprintf("%s/%s", hostsURL, endpoint.HostId)
	err = ipam.client.Get(hostInfoURL, &host)

	if err != nil {
		log.Errorf("IPAM: Encountered an error querying topology for hosts: %v", err)
		return nil, err
	}

	tenantUrl, err := ipam.client.GetServiceUrl("tenant")
	if err != nil {
		log.Errorf("IPAM: Encountered an error getting tenant srevice URL: %v", err)
		return nil, err
	}

	// TODO follow links once tenant service supports it. For now...

	t := &common.Tenant{}
	tenantsUrl := fmt.Sprintf("%s/tenants/%s", tenantUrl, endpoint.TenantID)
	err = ipam.client.Get(tenantsUrl, t)
	if err != nil {
		log.Errorf("IPAM: Encountered an error querying tenant service for tenant %s: %v", endpoint.TenantID, err)
		return nil, err
	}

	segmentUrl := fmt.Sprintf("/tenants/%s/segments/%s", endpoint.TenantID, endpoint.SegmentID)
	segment := &common.Segment{}
	err = ipam.client.Get(segmentUrl, segment)
	if err != nil {
		log.Errorf("IPAM: Encountered an error querying tenant service for tenant %s and segment %s: %v", endpoint.TenantID, endpoint.SegmentID, err)
		return nil, err
	}

	log.Debugf("IPAM: Constructing IP from Host IP %s, Tenant %d (%s %d), Segment %d (%s %d)", host.RomanaIp, t.NetworkID, t.Name, t.ID, segment.NetworkID, segment.Name, segment.ID)

	segmentBitShift := 32 - ipam.dc.PrefixBits - ipam.dc.PortBits - ipam.dc.TenantBits - ipam.dc.SegmentBits
	//	prefixBitShift := 32 - ipam.dc.PrefixBits
	tenantBitShift := segmentBitShift + ipam.dc.SegmentBits
	_, network, err := net.ParseCIDR(host.RomanaIp)
	if err != nil {
		log.Errorf("IPAM: Encountered an error parsing %s: %v", host.RomanaIp, err)
		return nil, err
	}
	hostIpInt := common.IPv4ToInt(network.IP)
	upToEndpointIpInt := hostIpInt | (t.NetworkID << tenantBitShift) | (segment.NetworkID << segmentBitShift)

	log.Tracef(trace.Inside, "IPAM: Before calling addIPAMEndpoint:  %v | (%v << %v) | (%v << %v): %v ", network.IP.String(), t.NetworkID, tenantBitShift, segment.NetworkID, segmentBitShift, common.IntToIPv4(upToEndpointIpInt))
	err = ipam.store.addEndpoint(endpoint, upToEndpointIpInt, ipam.dc)
	if err != nil {
		log.Errorf("IPAM: Encountered an error allocating IP: %s", err)
		return nil, err
	}

	log.Infof("IPAM: Allocated IP (%s) for Endpoint (%s) on HostID (%s)",
		endpoint.Ip, endpoint.Name, endpoint.HostId)

	return endpoint, nil
}

// deleteEndpoint releases the IP(s) owned by the IPAMEndpoint into assignable
// pool.
func (ipam *IPAM) deleteEndpoint(input interface{}, ctx common.RestContext) (interface{}, error) {
	ipam.Lock()
	defer ipam.Unlock()

	ip := ctx.PathVariables["ip"]
	log.Printf("IPAM: Attempting to deallocate %s", ip)
	ep, err := ipam.store.deleteEndpoint(ip)
	if err == nil {
		log.Infof("IPAM: Deallocated %s (%s)", ip, ep.Name)
	} else {
		log.Errorf("IPAM: Error deallocating %s: %s", ip, err)
	}
	return ep, err
}

// listEndpoints returns all registered endpoints
func (ipam *IPAM) listEndpoints(input interface{}, ctx common.RestContext) (interface{}, error) {
	ipam.RLock()
	defer ipam.RUnlock()

	return ipam.store.listEndpoint()
}

// Name provides name of this service.
func (ipam *IPAM) Name() string {
	return "ipam"
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (ipam *IPAM) SetConfig(config common.ServiceConfig) error {
	ipam.Lock()
	defer ipam.Unlock()

	ipam.config = config
	storeConfigMap := config.ServiceSpecific["store"].(map[string]interface{})
	rdbmsStore, err := store.GetStore(storeConfigMap)
	if err != nil {
		return err
	}
	ipam.store.RdbmsStore = rdbmsStore.(*store.RdbmsStore)
	ipam.store.ServiceStore = &ipam.store
	return nil
}

func (ipam *IPAM) CreateSchema(overwrite bool) error {
	ipam.Lock()
	defer ipam.Unlock()

	return ipam.store.CreateSchema(overwrite)
}

// Initialize implements Initialize method of Service interface
func (ipam *IPAM) Initialize(client *common.RestClient) error {
	ipam.Lock()
	defer ipam.Unlock()

	log.Println("Entering ipam.Initialize()")
	err := ipam.store.Connect()
	if err != nil {
		return err
	}
	ipam.client = client
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl("topology")
	if err != nil {
		return err
	}

	index := common.IndexResponse{}
	err = ipam.client.Get(topologyURL, &index)
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
