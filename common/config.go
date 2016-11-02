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

package common

// Configuration-related code.

import (
	"errors"
	"fmt"
	"github.com/go-yaml/yaml"
	"github.com/golang/glog"
	"io/ioutil"

	"path/filepath"
)

// Hook defines an executable to run before or after any
// Route handler execution.
type Hook struct {
	// Executable to run
	Executable string `json:"executable"`
	// Pattern to match in common.Route
	Pattern string `json:"pattern"`
	// HTTP method to match
	Method string `json:"method"`
	// Whether to run before or after the handler for the pattern/method
	// pair is invoked
	When string `json:"when"`
	// Where to write output (if omitted, will be just logged)
	Output string `json:"output"`
}

const (
	RestRetryStrategyExponential = "exponential"
	RestRetryStrategyFibonacci   = "fibonacci"
)

// Api part of service configuration (host/port).
type Api struct {
	// Host to listen on.
	Host string `yaml:"host" json:"host"`
	// Port to listen on.
	Port uint64 `yaml:"port" json:"port"`
	// Root service URL
	RootServiceUrl string `json:"root_service_url,omitempty" yaml:"root_service_url,omitempty"`
	// Rest timeout in milliseconds (if omitted, defaults to DefaultRestTimeout)
	RestTimeoutMillis int64  `yaml:"rest_timeout_millis,omitempty" json:"rest_timeout_millis,omitempty"`
	RestRetries       int    `yaml:"rest_retries,omitempty" json:"rest_retries,omitempty"`
	RestRetryStrategy string `yaml:"rest_retry_strategy,omitempty" yaml:"rest_retry_strategy,json"`
	// Location of the public key.
	AuthPublic   string `yaml:"auth_public" json:"auth_public"`
	RestTestMode bool   `yaml:"rest_test_mode,omitempty" json:"rest_test_mode,omitempty"`
	Hooks        []Hook
}

func (api Api) GetHostPort() string {
	return fmt.Sprintf("%s:%d", api.Host, api.Port)
}

// CommonConfig stores configuration that is common to all services.
// For things such as API information (host/port),
// DB, etc.
type CommonConfig struct {
	Api *Api `yaml:"api" json:"api"`
	// Credential is convenient to store here but it is not part of the
	// configuration that is passed around in JSON.
	Credential *Credential `yaml:"-" json:"-"`
	PublicKey  []byte      `yaml:"-" json:"-"`
}

// ServiceConfig contains common configuration
// for each service and also a section for
// service-specific configuration. This may be
// an overkill but if we have a type system, we should
// use it instead of just dictionaries.
type ServiceConfig struct {
	Common CommonConfig `json:"common" yaml:"common"`
	// TODO I really dislike this name, but there
	// should be some common part that's applicable
	// to all services, and something service-specific
	// that we in common do not need to know about.
	ServiceSpecific map[string]interface{} `json:"config" yaml:"config,omitempty"`
}

// Config provides the main configuration object
type Config struct {
	Services map[string]ServiceConfig
}

type yamlConfig struct {
	Services []yamlServiceConfig `yaml:"services"`
}

type yamlServiceConfig struct {
	Service string
	Api     *Api
	Config  map[string]interface{} `yaml:"config,omitempty"`
}

// cleanupMap ensures that map[string]interface{}'s children
// maps have strings as keys, not interfaces. YAML parses a
// file into a map[interface{}]interface{} structure which JSON
// then cannot marshal.
func cleanupMap(m map[string]interface{}) map[string]interface{} {
	retval := make(map[string]interface{})
	for k, v := range m {
		switch vt := v.(type) {
		case map[interface{}]interface{}:
			newVal := cleanupMap2(vt)
			retval[k] = newVal
		default:
			retval[k] = v
		}
	}
	return retval
}

// cleanupMap2 is called from cleanupMap
func cleanupMap2(ifcIfc map[interface{}]interface{}) map[string]interface{} {
	retval := make(map[string]interface{})
	for k, v := range ifcIfc {
		kStr := k.(string)
		switch vt := v.(type) {
		case map[interface{}]interface{}:
			newVal := cleanupMap2(vt)
			retval[kStr] = newVal
		default:
			retval[kStr] = v
		}
	}
	return retval
}

// ReadConfig parses the configuration file provided and returns
// ReadConfig reads config from file to structure
func ReadConfig(fname string) (Config, error) {
	// Created new...
	config := &Config{}

	absFname, err := filepath.Abs(fname)
	if err != nil {
		return *config, err
	}
	if fname != absFname {
		glog.V(1).Infof("ReadConfig(): Normalized %s to %s", fname, absFname)
		fname = absFname
	}
	yamlConfig := yamlConfig{}
	if fname != "" {
		data, err := ioutil.ReadFile(fname)
		if err != nil {
			return *config, err
		}
		err = yaml.Unmarshal(data, &yamlConfig)
		if err != nil {
			glog.V(1).Infof("ReadConfig(): Error reading config: %v", err)
			return *config, err
		}
		serviceConfigs := yamlConfig.Services
		config.Services = make(map[string]ServiceConfig)
		// Now convert this to map for easier reading...
		for i := range serviceConfigs {
			c := serviceConfigs[i]
			api := Api{Host: c.Api.Host, Port: c.Api.Port, Hooks: c.Api.Hooks}
			cleanedConfig := cleanupMap(c.Config)
			commonConfig := CommonConfig{Api: &api, Credential: nil, PublicKey: nil}
			config.Services[c.Service] = ServiceConfig{Common: commonConfig, ServiceSpecific: cleanedConfig}
		}
		return *config, nil
	}
	return *config, errors.New("Empty filename.")
}

// WriteConfig writes config from file to structure
func WriteConfig(config Config, fname string) error {
	yamlConfig := &yamlConfig{}
	yamlConfig.Services = make([]yamlServiceConfig, len(config.Services))
	i := 0
	for k, v := range config.Services {
		ysc := &yamlServiceConfig{}
		ysc.Service = k
		ysc.Api = v.Common.Api
		ysc.Config = v.ServiceSpecific
		yamlConfig.Services[i] = *ysc
		i++
	}

	b, err := yaml.Marshal(yamlConfig)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fname, b, 0777)
}
