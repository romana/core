// Copyright (c) 2016 Pani Networks
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

/*
Implements root service
*/
package root

import (
	//	"fmt"
	"github.com/romana/core/common"
	"strconv"
	"log"
	"strings"
	//	"github.com/gorilla/mux"
)

// Root-specific configuration. This may seem a bit
// convoluted, but it is convoluted only for root - for this
// cost we are buying simplicity/uniformity for other services.
// See SetConfig() func.
type Config struct {
	// This is the common part
	common *common.CommonConfig
	// In here we are going to store contents
	// of the entire config file.
	full *common.Config
}

type Root struct {
	config Config
	routes common.Route
}

const fullConfigKey = "fullConfig"

// SetConfig implements SetConfig function of the Service interface
func (root *Root) SetConfig(config common.ServiceConfig) error {
	root.config = Config{}
	root.config.common = &config.Common
	f := config.ServiceSpecific[fullConfigKey].(common.Config)
	root.config.full = &f

	return nil
}

func (root *Root) Initialize() error {
	return nil
}

// Handler for the / URL
// See https://github.com/romanaproject/romana/wiki/Root-service-API
func (root *Root) handlePortUpdate(input interface{}, ctx common.RestContext) (interface{}, error) {
	portUpdateMsg := input.(*common.PortUpdateMessage)
	pathVars := ctx.PathVariables
	serviceName := pathVars["serviceName"]
	serviceConfig := root.config.full.Services[serviceName]
	oldPort := serviceConfig.Common.Api.Port
	serviceConfig.Common.Api.Port = portUpdateMsg.Port
	log.Printf("Root service: registering port %d for service %s (was %d)\n", serviceConfig.Common.Api.Port, serviceName, oldPort)
	return nil, nil
}

// Handler for the / URL
// See https://github.com/romanaproject/romana/wiki/Root-service-API
func (root *Root) handleIndex(input interface{}, ctx common.RestContext) (interface{}, error) {
	retval := common.RootIndexResponse{}

	retval.ServiceName = "root"
	myUrl := strings.Join([]string{"http://", root.config.common.Api.Host, ":", strconv.FormatUint(root.config.common.Api.Port, 10)}, "")

	// Links has links to config URLs for now, but also self - hence plus one
	retval.Links = make([]common.LinkResponse, len(root.config.full.Services)+1)

	retval.Services = make([]common.ServiceResponse, len(root.config.full.Services))
	i := 0
	for key, value := range root.config.full.Services {
		retval.Services[i] = common.ServiceResponse{}
		retval.Services[i].Name = key
		href := "http://" + value.Common.Api.GetHostPort()
		link := common.LinkResponse{Rel: "service", Href: href}
		retval.Services[i].Links = []common.LinkResponse{link}
		configLink := common.LinkResponse{"/config/" + key, key + "-config"}
		retval.Links[i] = configLink
		i++
	}
	retval.Links[i] = common.LinkResponse{myUrl, "self"}

	return retval, nil
}

func (root *Root) Name() string {
	return "root"
}

// Handler for the /config
func (root *Root) handleConfig(input interface{}, ctx common.RestContext) (interface{}, error) {
	pathVars := ctx.PathVariables
	serviceName := pathVars["serviceName"]
	retval := root.config.full.Services[serviceName]
	return retval, nil
}


// Provides Routes
func (root Root) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			"GET",
			"/",
			root.handleIndex,
			nil,
		},
		common.Route{
			"GET",
			"/config/{serviceName}",
			root.handleConfig,
			nil,
		},
		common.Route{
			"POST",
			"/config/{serviceName}/port",
			root.handlePortUpdate,
			func() interface{} {
				return &common.PortUpdateMessage{}
			},
		},
	}
	return routes
}

// Runs root service
func Run(configFileName string) (chan common.ServiceMessage, string, error) {
	fullConfig, err := common.ReadConfig(configFileName)
	if err != nil {
		return nil, "", err
	}

	rootService := &Root{}
	rootServiceConfig := common.ServiceConfig{fullConfig.Services["root"].Common, make(map[string]interface{})}
	rootServiceConfig.ServiceSpecific[fullConfigKey] = fullConfig
	return common.InitializeService(rootService, rootServiceConfig)
}
