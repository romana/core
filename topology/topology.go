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

package topology

import (
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/common/store"
	"log"
	"net"
	"strconv"
	"strings"
)

// TopologySvc service
type TopologySvc struct {
	client     *common.RestClient
	config     common.ServiceConfig
	datacenter *common.Datacenter
	store      common.Store
	routes     common.Route
}

const (
	infoListPath  = "/info"
	agentListPath = "/agents"
	hostListPath  = "/hosts"
	torListPath   = "/tors"
	spineListPath = "/spines"
	dcPath        = "/datacenter"
)

// Routes returns various routes used in the service.
func (topology *TopologySvc) Routes() common.Routes {
	infoRouteIndex := common.Route{
		Method:          "GET",
		Pattern:         "/",
		Handler:         topology.handleIndex,
		MakeMessage:     nil,
		UseRequestToken: false,
	}
	routes := common.Routes{
		infoRouteIndex,
		common.Route{
			Method:          "GET",
			Pattern:         hostListPath,
			Handler:         topology.handleHostListGet,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "POST",
			Pattern:         hostListPath,
			Handler:         topology.handleHostListPost,
			MakeMessage:     func() interface{} { return &common.Host{} },
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         hostListPath + "/{hostId}",
			Handler:         topology.handleGetHost,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         dcPath,
			Handler:         topology.handleDc,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "DELETE",
			Pattern:         hostListPath + "/{hostID}",
			Handler:         topology.handleDeleteHost,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		// TODO to be done generically
		common.Route{
			Method:          "GET",
			Pattern:         "/findLast/hosts",
			Handler:         topology.handleFindHost,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
	}

	// TODO reintroduce (if we need to) the find routes
	//	var h = []common.Host{}
	//	routes = append(routes, common.CreateFindRoutes(&h, &topology.store.DbStore)...)
	return routes
}

func (topology *TopologySvc) handleFindHost(input interface{}, ctx common.RestContext) (interface{}, error) {
	query := ctx.QueryVariables
	var hosts []common.Host
	return topology.store.Find(query, &hosts, common.FindLast)
}

// handleHost handles request for a specific host's info
func (topology *TopologySvc) handleDc(input interface{}, ctx common.RestContext) (interface{}, error) {
	// For now it's from config, later on we can use this to manage multiple dcs.
	return topology.datacenter, nil
}

// Name implements method of Service interface.
func (topology *TopologySvc) Name() string {
	return "topology"
}

// handleGetHost handles request for a specific host's info
func (topology *TopologySvc) handleGetHost(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In handleHost()")
	idStr := ctx.PathVariables["hostId"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	host, err := topology.store.GetHost(id)
	if err != nil {
		return nil, err
	}
	agentURL := fmt.Sprintf("http://%s:%d", host.Ip, host.AgentPort)
	agentLink := common.LinkResponse{Href: agentURL, Rel: "agent"}
	hostLink := common.LinkResponse{Href: hostListPath + "/" + idStr, Rel: "self"}
	collectionLink := common.LinkResponse{Href: hostListPath, Rel: "self"}
	host.Links = []common.LinkResponse{agentLink, hostLink, collectionLink}
	return host, nil
}

func (topology *TopologySvc) handleHostListGet(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In handleHostListGet()")
	hosts, err := topology.store.ListHosts()
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

// handleHostListPost handles addition of a host to the current datacenter.
// If the Host.AgentPort is not specified, root service is queried for
// the default Agent port.
func (topology *TopologySvc) handleHostListPost(input interface{}, ctx common.RestContext) (interface{}, error) {
	host := input.(*common.Host)
	var err error

	// If no agent port is specfied in the creation of new host,
	// get the agent port from root service.
	log.Printf("Host requested with agent port %d", host.AgentPort)
	if host.AgentPort == 0 {
		// Get the one from configuration
		agentConfig, err := topology.client.GetServiceConfig("agent")
		if err != nil {
			return nil, err
		}
		host.AgentPort = agentConfig.Common.Api.Port
		if host.AgentPort == 0 {
			return nil, common.NewError500("Cannot determine port for agent")
		}
	}
	log.Printf("Host will be added with agent port %d", host.AgentPort)
	err = topology.store.AddHost(*topology.datacenter, host)
	if err != nil {
		return nil, err
	}
	agentURL := fmt.Sprintf("http://%s:%d", host.Ip, host.AgentPort)
	agentLink := common.LinkResponse{Href: agentURL, Rel: "agent"}
	hostLink := common.LinkResponse{Href: hostListPath + "/" + fmt.Sprintf("%d", host.ID), Rel: "self"}
	collectionLink := common.LinkResponse{Href: hostListPath, Rel: "self"}
	host.Links = []common.LinkResponse{agentLink, hostLink, collectionLink}
	return host, nil
}

func (topology *TopologySvc) handleIndex(input interface{}, ctx common.RestContext) (interface{}, error) {
	retval := common.IndexResponse{}
	retval.ServiceName = "topology"
	myURL := strings.Join([]string{"http://", topology.config.Common.Api.Host, ":", strconv.FormatUint(topology.config.Common.Api.Port, 10)}, "")

	selfLink := common.LinkResponse{Href: myURL, Rel: "self"}
	aboutLink := common.LinkResponse{Href: infoListPath, Rel: "about"}
	agentsLink := common.LinkResponse{Href: agentListPath, Rel: "agent-list"}
	hostsLink := common.LinkResponse{Href: hostListPath, Rel: "host-list"}
	torsLink := common.LinkResponse{Href: torListPath, Rel: "tor-list"}
	spinesLink := common.LinkResponse{Href: spineListPath, Rel: "spine-list"}
	dcLink := common.LinkResponse{Href: dcPath, Rel: "datacenter"}

	retval.Links = []common.LinkResponse{selfLink, aboutLink, agentsLink, hostsLink, torsLink, spinesLink, dcLink}
	return retval, nil
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (topology *TopologySvc) SetConfig(config common.ServiceConfig) error {
	topology.config = config
	dcMap := config.ServiceSpecific["datacenter"].(map[string]interface{})
	dc := common.Datacenter{}
	dc.IpVersion = uint(dcMap["ip_version"].(float64))
	if dc.IpVersion != 4 {
		return common.NewError("Only IPv4 is currently supported.")
	}
	dc.Cidr = dcMap["cidr"].(string)
	_, ipNet, err := net.ParseCIDR(dc.Cidr)
	if err != nil {
		return err
	}
	prefixBits, _ := ipNet.Mask.Size()
	dc.PrefixBits = uint(prefixBits)

	dc.PortBits = uint(dcMap["host_bits"].(float64))
	dc.TenantBits = uint(dcMap["tenant_bits"].(float64))
	dc.SegmentBits = uint(dcMap["segment_bits"].(float64))
	dc.EndpointBits = uint(dcMap["endpoint_bits"].(float64))
	dc.EndpointSpaceBits = uint(dcMap["endpoint_space_bits"].(float64))
	if dc.EndpointBits == 0 {
		return common.NewError("Endpoint bits may not be 0")
	}
	bitSum := dc.PrefixBits + dc.PortBits + dc.TenantBits + dc.SegmentBits + dc.EndpointBits + dc.EndpointSpaceBits
	if bitSum != 32 {
		bitSumStr := fmt.Sprintf("%s+%d+%d+%d+%d+%d", dc.Cidr, dc.PortBits, dc.TenantBits, dc.SegmentBits, dc.EndpointBits, dc.EndpointSpaceBits)
		return common.NewError("Sum of prefix, port, tenant, segment, endpoint and endpoint space bits must be exactly 32, but it is %s=%d", bitSumStr, bitSum)
	}

	// TODO this should have worked but it doesn't...
	//	err := mapstructure.Decode(dcMap, &dc)
	//	if err != nil {
	//		return err
	//	}
	log.Printf("Datacenter information: was %s, decoded to %+v\n", dcMap, dc)
	topology.datacenter = &dc

	storeConfigMap := config.ServiceSpecific["store"].(map[string]interface{})
	topology.store, err = store.GetStore(storeConfigMap)
	return err
}

// Initialize the topology service
func (topology *TopologySvc) Initialize(client *common.RestClient) error {
	log.Println("Parsing", topology.datacenter)

	ip, _, err := net.ParseCIDR(topology.datacenter.Cidr)
	if err != nil {
		return err
	}
	topology.client = client
	topology.datacenter.Prefix = common.IPv4ToInt(ip)
	return topology.store.Connect()
}

func (topology *TopologySvc) CreateSchema(overwrite bool) error {
	return topology.store.CreateSchema(overwrite)
}

// handleDeleteHost handles deletion of a host.
func (topology *TopologySvc) handleDeleteHost(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In handleDeleteHost()")
	idStr := strings.TrimSpace(ctx.PathVariables["hostID"])
	if idStr == "" {
		return nil, common.NewError400("Request must be to /hosts/{hostID}.")
	}
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	err = topology.store.DeleteHost(id)
	if err != nil {
		return nil, err
	}
	return nil, nil
}
