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

package topology

import (
	"errors"
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
	store      topologyStore
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

// Provides Routes
func (topology *TopologySvc) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			"GET",
			"/",
			topology.handleIndex,
			nil,
		},
		common.Route{
			"GET",
			hostListPath,
			topology.handleHostListGet,
			nil,
		},
		common.Route{
			"POST",
			hostListPath,
			topology.handleHostListPost,
			func() interface{} {
				return &common.HostMessage{}
			},
		},
		common.Route{
			"GET",
			hostListPath + "/{hostId}",
			topology.handleHost,
			nil,
		},
		common.Route{
			"GET",
			dcPath,
			topology.handleDc,
			nil,
		},
	}
	return routes
}

type HostListMessage []common.HostMessage

// handleHost handles request for a specific host's info
func (topology *TopologySvc) handleDc(input interface{}, ctx common.RestContext) (interface{}, error) {
	// For now it's from config, later on we can use this to manage multiple dcs.
	return topology.datacenter, nil
}

func (topology *TopologySvc) Name() string {
	return "topology"
}

// handleHost handles request for a specific host's info
func (topology *TopologySvc) handleHost(input interface{}, ctx common.RestContext) (interface{}, error) {
	idStr := ctx.PathVariables["hostId"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	host, err := topology.store.findHost(id)
	if err != nil {
		return nil, err
	}
	agentUrl := fmt.Sprintf("http://%s:%d", host.Ip, host.AgentPort)
	agentLink := common.LinkResponse{agentUrl, "agent"}
	hostLink := common.LinkResponse{hostListPath + "/" + idStr, "self"}
	collectionLink := common.LinkResponse{hostListPath, "self"}

	links := []common.LinkResponse{agentLink, hostLink, collectionLink}
	hostIdStr := strconv.FormatUint(host.Id, 10)
	hostMessage := common.HostMessage{Id: hostIdStr, RomanaIp: host.RomanaIp, Ip: host.Ip, Name: host.Name, AgentPort: int(host.AgentPort), Links: links}
	return hostMessage, nil
}

func (topology *TopologySvc) handleHostListGet(input interface{}, ctx common.RestContext) (interface{}, error) {
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
	id, err := topology.store.addHost(host)
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
	myUrl := strings.Join([]string{"http://", topology.config.Common.Api.Host, ":", strconv.FormatUint(topology.config.Common.Api.Port, 10)}, "")

	selfLink := common.LinkResponse{myUrl, "self"}
	aboutLink := common.LinkResponse{infoListPath, "about"}
	agentsLink := common.LinkResponse{agentListPath, "agent-list"}
	hostsLink := common.LinkResponse{hostListPath, "host-list"}
	torsLink := common.LinkResponse{torListPath, "tor-list"}
	spinesLink := common.LinkResponse{spineListPath, "spine-list"}
	dcLink := common.LinkResponse{dcPath, "datacenter"}

	retval.Links = []common.LinkResponse{selfLink, aboutLink, agentsLink, hostsLink, torsLink, spinesLink, dcLink}
	return retval, nil
}

// Backing store
type topologyStore interface {
	validateConnectionInformation() error
	connect() error
	createSchema(overwrite bool) error
	addHost(host Host) (string, error)
	listHosts() ([]Host, error)
	findHost(id uint64) (Host, error)
	setConfig(config map[string]interface{}) error
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
	dc.PortBits = uint(dcMap["host_bits"].(float64))
	dc.TenantBits = uint(dcMap["tenant_bits"].(float64))
	dc.SegmentBits =uint( dcMap["segment_bits"].(float64))
	dc.EndpointBits = uint(dcMap["endpoint_bits"].(float64))
	dc.EndpointSpaceBits =uint( dcMap["endpoint_space_bits"].(float64))
	// TODO this should have worked but it doesn't...
	//	err := mapstructure.Decode(dcMap, &dc)
	//	if err != nil {
	//		return err
	//	}
	log.Printf("Datacenter information: was %s, decoded to %s\n", dcMap, dc)
	topology.datacenter = &dc
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	storeType := strings.ToLower(storeConfig["type"].(string))
	switch storeType {
	case "mysql":
		topology.store = &mysqlStore{}

	case "mock":
		topology.store = &mockStore{}

	default:
		return errors.New("Unknown store type: " + storeType)
	}
	return topology.store.setConfig(storeConfig)
}

// Runs topology service
func Run(rootServiceUrl string) (chan common.ServiceMessage, error) {
	topSvc := &TopologySvc{}
	config, err := common.GetServiceConfig(rootServiceUrl, topSvc)
	if err != nil {
		return nil, err
	}
	ch, err := common.InitializeService(topSvc, *config)
	return ch, err
}

func (topology *TopologySvc) Initialize() error {
	log.Println("Parsing", topology.datacenter)
	ip, _, err := net.ParseCIDR(topology.datacenter.Cidr)
	if err != nil {
		return err
	}
	topology.datacenter.Prefix = common.IPv4ToInt(ip)
	return topology.store.connect()
}

// Runs topology service
func CreateSchema(rootServiceUrl string, overwrite bool) error {
	log.Println("In CreateSchema(", rootServiceUrl, ",", overwrite, ")")
	topologyService := &TopologySvc{}
	config, err := common.GetServiceConfig(rootServiceUrl, topologyService)
	if err != nil {
		return err
	}

	err = topologyService.SetConfig(*config)
	if err != nil {
		return err
	}
	return topologyService.store.createSchema(overwrite)
}
