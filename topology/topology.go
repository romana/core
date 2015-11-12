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
	"github.com/romana/core/common"
	"strconv"
	"strings"
)

// Topology service
type Topology struct {
	config common.ServiceConfig
	store  topologyStore
	routes common.Route
}

const (
	infoListPath  = "/info"
	agentListPath = "/agents"
	hostListPath  = "/hosts"
	torListPath   = "/tors"
	spineListPath = "/spines"
	dcListPath    = "/datacenters"
)

// Provides Routes
func (topology *Topology) Routes() common.Routes {
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
	}
	return routes
}

type HostListMessage []common.HostMessage

// handleHost handles request for a specific host's info
func (topology *Topology) handleHost(input interface{}, ctx common.RestContext) (interface{}, error) {
	idStr := ctx.PathVariables["hostId"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	host, err := topology.store.findHost(id)
	if err != nil {
		return nil, err
	}
	agentUrl := strings.Join([]string{"http://", host.Ip, ":", strconv.FormatUint(host.AgentPort, 10)}, "")
	agentLink := common.LinkResponse{agentUrl, "agent"}
	hostLink := common.LinkResponse{hostListPath + "/" + idStr, "self"}
	collectionLink := common.LinkResponse{hostListPath, "self"}

	links := []common.LinkResponse{agentLink, hostLink, collectionLink}
	hostMessage := common.HostMessage{Id: strconv.FormatUint(host.Id, 10), Ip: host.Ip, Name: host.Name, AgentPort: int(host.AgentPort), Links: links}
	return hostMessage, nil
}

func (topology *Topology) handleHostListGet(input interface{}, ctx common.RestContext) (interface{}, error) {
	hosts, err := topology.store.listHosts()
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

func (topology *Topology) handleHostListPost(input interface{}, ctx common.RestContext) (interface{}, error) {
	hostMessage := input.(*common.HostMessage)
	host := Host{Ip: hostMessage.Ip, Name: hostMessage.Name, AgentPort: uint64(hostMessage.AgentPort)}
	id, err := topology.store.addHost(host)
	if err != nil {
		return nil, err
	}
	returnHostMessage := hostMessage
	fmt.Println("Added host",hostMessage)
	returnHostMessage.Id = id

	return returnHostMessage, nil
}

func (topology *Topology) handleIndex(input interface{}, ctx common.RestContext) (interface{}, error) {
	retval := common.IndexResponse{}
	retval.ServiceName = "topology"
	myUrl := strings.Join([]string{"http://", topology.config.Common.Api.Host, ":", strconv.FormatUint(topology.config.Common.Api.Port, 10)}, "")

	selfLink := common.LinkResponse{myUrl, "self"}
	aboutLink := common.LinkResponse{infoListPath, "about"}
	agentsLink := common.LinkResponse{agentListPath, "agent-list"}
	hostsLink := common.LinkResponse{hostListPath, "host-list"}
	torsLink := common.LinkResponse{torListPath, "tor-list"}
	spinesLink := common.LinkResponse{spineListPath, "spine-list"}
	dcsLink := common.LinkResponse{dcListPath, "datacenter-list"}

	retval.Links = []common.LinkResponse{selfLink, aboutLink, agentsLink, hostsLink, torsLink, spinesLink, dcsLink}
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
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (topology *Topology) SetConfig(config common.ServiceConfig) error {
	fmt.Println(config)
	topology.config = config
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})

	storeType := strings.ToLower(storeConfig["type"].(string))
	switch storeType {
	case "mysql":
		mysqlStore := &mysqlStore{}
		topology.store = mysqlStore
		return mysqlStore.setConfig(storeConfig)

	default:
		return errors.New("Unknown store type: " + storeType)
	}
	return nil
}

func (topology *Topology) createSchema(overwrite bool) error {
	return topology.store.createSchema(overwrite)
}

// Runs topology service
func Run(rootServiceUrl string) (chan common.ServiceMessage, error) {
	topologyService := &Topology{}
	config, err := common.GetServiceConfig(rootServiceUrl, "topology")
	if err != nil {
		return nil, err
	}
	ch, err := common.InitializeService(topologyService, *config)
	return ch, err
}

func (topology *Topology) Initialize() error {
	return topology.store.connect()
}

// Runs topology service
func CreateSchema(rootServiceUrl string, overwrite bool) error {
	fmt.Println("In CreateSchema(", rootServiceUrl, ",", overwrite, ")")
	topologyService := &Topology{}
	config, err := common.GetServiceConfig(rootServiceUrl, "topology")
	if err != nil {
		return err
	}

	err = topologyService.SetConfig(*config)
	if err != nil {
		return err
	}
	return topologyService.createSchema(overwrite)
}
