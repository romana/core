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
	//	"github.com/mitchellh/mapstructure"
	"github.com/romana/core/common"
	"log"
	"net"
	"strconv"
	"strings"
)

// TopologySvc service
type TopologySvc struct {
	config     common.ServiceConfig
	datacenter *common.Datacenter
	store      topoStore
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
	routes := common.Routes{
		common.Route{
			Method:          "GET",
			Pattern:         "/",
			Handler:         topology.handleIndex,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
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
			MakeMessage:     func() interface{} { return &common.HostMessage{} },
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         hostListPath + "/{hostId}",
			Handler:         topology.handleHost,
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
	}
	return routes
}

// HostListMessage is just a list of common.HostMessage
type HostListMessage []common.HostMessage

// handleHost handles request for a specific host's info
func (topology *TopologySvc) handleDc(input interface{}, ctx common.RestContext) (interface{}, error) {
	// For now it's from config, later on we can use this to manage multiple dcs.
	return topology.datacenter, nil
}

// Name implements method of Service interface.
func (topology *TopologySvc) Name() string {
	return "topology"
}

// handleHost handles request for a specific host's info
func (topology *TopologySvc) handleHost(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In handleHost()")
	idStr := ctx.PathVariables["hostId"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	host, err := topology.store.findHost(id)
	if err != nil {
		return nil, err
	}
	agentURL := fmt.Sprintf("http://%s:%d", host.Ip, host.AgentPort)
	agentLink := common.LinkResponse{Href: agentURL, Rel: "agent"}
	hostLink := common.LinkResponse{Href: hostListPath + "/" + idStr, Rel: "self"}
	collectionLink := common.LinkResponse{Href: hostListPath, Rel: "self"}

	links := []common.LinkResponse{agentLink, hostLink, collectionLink}
	hostIDStr := strconv.FormatUint(host.Id, 10)
	hostMessage := common.HostMessage{Id: hostIDStr, RomanaIp: host.RomanaIp, Ip: host.Ip, Name: host.Name, AgentPort: int(host.AgentPort), Links: links}
	return hostMessage, nil
}

func (topology *TopologySvc) handleHostListGet(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In handleHostListGet()")
	hosts, err := topology.store.listHosts()
	if err != nil {
		return nil, err
	}
	// TODO nested structures or some sort of easy
	// way of translating between string and auto-increment ID.
	retval := make([]common.HostMessage, len(hosts))
	for i := range hosts {
		retval[i] = common.HostMessage{Ip: hosts[i].Ip, RomanaIp: hosts[i].RomanaIp, Name: hosts[i].Name, Id: strconv.FormatUint(hosts[i].Id, 10)}
	}
	return retval, nil
}

func (topology *TopologySvc) handleHostListPost(input interface{}, ctx common.RestContext) (interface{}, error) {
	hostMessage := input.(*common.HostMessage)
	host := Host{Ip: hostMessage.Ip, Name: hostMessage.Name, RomanaIp: hostMessage.RomanaIp, AgentPort: uint64(hostMessage.AgentPort)}
	id, err := topology.store.addHost(&host)
	if err != nil {
		return nil, err
	}
	returnHostMessage := hostMessage
	log.Println("Added host", hostMessage)
	returnHostMessage.Id = id

	return returnHostMessage, nil
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
	log.Println(config)
	topology.config = config
	dcMap := config.ServiceSpecific["datacenter"].(map[string]interface{})
	dc := common.Datacenter{}
	dc.IpVersion = uint(dcMap["ip_version"].(float64))
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
	// TODO this should have worked but it doesn't...
	//	err := mapstructure.Decode(dcMap, &dc)
	//	if err != nil {
	//		return err
	//	}
	log.Printf("Datacenter information: was %s, decoded to %#v\n", dcMap, dc)
	topology.datacenter = &dc
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	topology.store = topoStore{}
	topology.store.ServiceStore = &topology.store
	return topology.store.SetConfig(storeConfig)
}

// Run configures and runs topology service.
func Run(rootServiceURL string, cred *common.Credential) (*common.RestServiceInfo, error) {
	clientConfig := common.GetDefaultRestClientConfig()
	clientConfig.Credential = cred
	client, err := common.NewRestClient(rootServiceURL, clientConfig)
	if err != nil {
		return nil, err
	}
	topSvc := &TopologySvc{}
	config, err := client.GetServiceConfig(rootServiceURL, topSvc)
	if err != nil {
		return nil, err
	}

	return common.InitializeService(topSvc, *config)

}

// Initialize the topology service
func (topology *TopologySvc) Initialize() error {
	log.Println("Parsing", topology.datacenter)
	ip, _, err := net.ParseCIDR(topology.datacenter.Cidr)
	if err != nil {
		return err
	}
	topology.datacenter.Prefix = common.IPv4ToInt(ip)
	return topology.store.Connect()
}

// CreateSchema creates schema for topology service.
func CreateSchema(rootServiceURL string, overwrite bool) error {
	log.Println("In CreateSchema(", rootServiceURL, ",", overwrite, ")")
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootServiceURL))
	if err != nil {
		return err
	}

	topologyService := &TopologySvc{}
	config, err := client.GetServiceConfig(topologyService)
	if err != nil {
		return err
	}

	err = topologyService.SetConfig(*config)
	if err != nil {
		return err
	}
	return topologyService.store.CreateSchema(overwrite)
}
