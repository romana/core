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

package common

import (
	"errors"
	"fmt"
	"github.com/go-yaml/yaml"
	"io/ioutil"
	//	"reflect"
)

// Api part of service configuration (host/port).
type Api struct {
	Host     string `yaml:"host" json:"host"`
	Port     uint64 `yaml:"port" json:"port"`
	RootHost string `yaml:"root_host" json:"root_host"`
	RootPort uint64 `yaml:"root_port" json:"root_port"`
}

// Configuration that is common to all services.
// For things such as API information (host/port),
// DB, etc.
type CommonConfig struct {
	Api Api `yaml:"api" json:"api"`
}

// ServiceConfig contains common configuration
// for each service and also a section for
// service-specific configuration. This may be
// an overkill but if we have a type system, we should
// use it instead of just dictionaries.
type ServiceConfig struct {
	Common *CommonConfig `yaml:"common" json:"common"`
	// TODO I really dislike this name, but there
	// should be some common part that's applicable
	// to all services, and something service-specific
	// that we in common do not need to know about.
	ServiceSpecific interface{} `yaml:"service_specific" json:"service_specific"`
}

// Main configuration object
type Config struct {
	Services map[string]*ServiceConfig
}

type yamlConfig struct {
	Services []yamlServiceConfig `yaml:"services"`
}

type yamlServiceConfig struct {
	Service string
	Api     Api
	Config  map[string]interface{}
}

// ReadConfig parses the configuration file provided and returns
// Config structure
func ReadConfig(fname string) (Config, error) {
	// Created new...
	config := &Config{}
	yamlConfig := yamlConfig{}
	if fname != "" {
		data, err := ioutil.ReadFile(fname)
		if err != nil {
			return *config, err
		}
		err = yaml.Unmarshal([]byte(data), &yamlConfig)
		if err != nil {
			return *config, err
		}
		serviceConfigs := yamlConfig.Services
		config.Services =make(map[string]*ServiceConfig)
		// Now convert this to map for easier reading...
		for i := range serviceConfigs {
			c := serviceConfigs[i]
			config.Services[c.Service] = &ServiceConfig{}
			api := c.Api
			config.Services[c.Service].Common = &CommonConfig{}
			config.Services[c.Service].Common.Api.Host = api.Host
			config.Services[c.Service].Common.Api.Port = api.Port
			
			config.Services[c.Service].ServiceSpecific = c.Config
		}
		fmt.Println("Read configuration from", fname)
		return *config, nil
	} else {
		return *config, errors.New("Empty filename.")
	}
}
