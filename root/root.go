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

/*
Implements root service
*/
package root

import (
	//	"fmt"
	"github.com/romanaproject/pani_core/common"
	"strconv"
	"strings"
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

// SetConfig implements SetConfig function of the Service interface
func (root *Root) SetConfig(config common.ServiceConfig) error {
	//	RootConfig{fullConfig.ServiceConfigs["root"], fullConfig}
	//
	root.config = Config{}
	root.config.common = config.Common
	fullConfig := config.ServiceSpecific
	aMap := fullConfig.(common.Config)
	root.config.full = &aMap
	return nil
}

// Handler for the / URL
// See https://github.com/romanaproject/romana/wiki/Root-service-API
func (root *Root) index(input interface{}) (interface{}, error) {
	retval := make(map[string]interface{})
	retval["serviceName"] = "root"

	selfMap := make(map[string]string)
	selfMap["href"] = strings.Join([]string{"http://", root.config.common.Api.Host, ":", strconv.FormatUint(root.config.common.Api.Port, 10)}, "")
	selfMap["rel"] = "self"

	retval["links"] = []map[string]string{selfMap}

	servicesList := make([]map[string]interface{}, len(root.config.full.Services))
	retval["services"] = servicesList
	i := 0
	for key, value := range root.config.full.Services {
		servicesList[i] = make(map[string]interface{})
		servicesList[i]["name"] = key
		servicesList[i]["links"] = make(map[string]string)
		servicesList[i]["links"].(map[string]string)["rel"] = "service"
		servicesList[i]["links"].(map[string]string)["href"] = strings.Join([]string{"http://", value.Common.Api.Host, ":", strconv.FormatUint(value.Common.Api.Port, 10)}, "")
		i++
	}
	return retval, nil
}

// Index is a handler for /
func Index(input interface{}) (interface{}, error) {
	return common.Config{}, nil
}

// Provides Routes
func (root Root) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			"GET",
			"/",
			root.index,
			nil,
			common.Config{},
		},
	}
	return routes
}

// Runs root service
func Run(configFileName string) (chan string, error) {

	fullConfig, err := common.ReadConfig(configFileName)
	if err != nil {
		return nil, err
	}

	rootService := &Root{}
	rootServiceConfig := common.ServiceConfig{}

	rootServiceConfig.Common = fullConfig.Services["root"].Common
	rootServiceConfig.ServiceSpecific = fullConfig

	ch, err := common.InitializeService(rootService, rootServiceConfig)
	return ch, err
}
