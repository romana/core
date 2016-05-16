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

// Package root implements root service.
package root

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/romana/core/common"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"
)

// Config provides Root-specific configuration. This may seem a bit
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
	//	routes     common.Routes
	privateKey []byte
	store      rootStore
}

const fullConfigKey = "fullConfig"

// SetConfig implements SetConfig function of the Service interface
func (root *Root) SetConfig(config common.ServiceConfig) error {
	log.Printf("Entering root.SetConfig(%v)", config)
	root.config = Config{}
	root.config.common = &config.Common
	f := config.ServiceSpecific[fullConfigKey].(common.Config)
	root.config.full = &f
	var err error
	root.store = rootStore{}
	root.store.ServiceStore = &root.store
	if config.ServiceSpecific["auth"] == nil {
		root.store.isAuthEnabled = false
	} else {
		root.store.isAuthEnabled, err = common.ToBool(config.ServiceSpecific["auth"].(string))
		if err != nil {
			return errors.New(fmt.Sprintf("Invalid value in field auth: %s", err.Error()))
		}
	}
	log.Printf("Checking auth: %t", root.store.isAuthEnabled)

	if root.store.isAuthEnabled {
		log.Printf("Auth is on!\n")
		privateKeyLocation := config.ServiceSpecific["authPrivate"].(string)
		log.Printf("Reading private key from %s", privateKeyLocation)
		root.privateKey, err = ioutil.ReadFile(privateKeyLocation)
		if err != nil {
			return err
		}

		storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
		return root.store.SetConfig(storeConfig)
	}
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

// Handler for the /auth URL
func (root *Root) handleAuth(input interface{}, ctx common.RestContext) (interface{}, error) {
	cred := input.(*common.Credential)
	// We assume just username/password for now
	roles, err := root.store.Authenticate(*cred)
	if err != nil {
		return nil, err
	}
	token := jwt.New(jwt.SigningMethodHS256)
	rolesStr := make([]string, len(roles))
	for i := range roles {
		rolesStr[i] = roles[i].Name()
	}
	token.Claims["roles"] = rolesStr
	token.Claims["iat"] = time.Now().Unix()
	// TODO make this configurable?
	token.Claims["exp"] = time.Now().Add(time.Second * 3600 * 24).Unix()
	jwtString, err := token.SignedString(root.privateKey)
	log.Printf("Signed token %v as %s", token, jwtString)
	return common.TokenMessage{Token: jwtString}, err
}

// Handler for the / URL
// See https://github.com/romanaproject/romana/wiki/Root-service-API
func (root *Root) handleIndex(input interface{}, ctx common.RestContext) (interface{}, error) {
	retval := common.RootIndexResponse{}

	retval.ServiceName = "root"
	myUrl := strings.Join([]string{"http://", root.config.common.Api.Host, ":", strconv.FormatUint(root.config.common.Api.Port, 10)}, "")

	// Links has links to config URLs for now, but also self - hence plus one
	retval.Links = make([]common.LinkResponse, len(root.config.full.Services)+2)

	retval.Services = make([]common.ServiceResponse, len(root.config.full.Services))
	i := 0
	for key, value := range root.config.full.Services {
		retval.Services[i] = common.ServiceResponse{}
		retval.Services[i].Name = key
		href := "http://" + value.Common.Api.GetHostPort()
		link := common.LinkResponse{Rel: "service", Href: href}
		retval.Services[i].Links = []common.LinkResponse{link}
		configLink := common.LinkResponse{Href: "/config/" + key, Rel: key + "-config"}
		retval.Links[i] = configLink
		i++
	}
	retval.Links[i] = common.LinkResponse{Href: myUrl, Rel: "self"}
	i++
	retval.Links[i] = common.LinkResponse{Href: "/auth", Rel: "auth"}
	return retval, nil
}

func (root *Root) Name() string {
	return common.ServiceRoot
}

// Handler for the /config
func (root *Root) handleConfig(input interface{}, ctx common.RestContext) (interface{}, error) {
	pathVars := ctx.PathVariables
	serviceName := pathVars["serviceName"]
	log.Printf("Received request for config of %s", serviceName)
	log.Printf("Looking for %s in %v", serviceName, root.config.full)
	retval := root.config.full.Services[serviceName]
	return retval, nil
}

// Routes provided by root service.
func (root *Root) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:          "GET",
			Pattern:         "/",
			Handler:         root.handleIndex,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "POST",
			Pattern:         common.AuthPath,
			Handler:         root.handleAuth,
			MakeMessage:     func() interface{} { return &common.Credential{} },
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         "/config/{serviceName}",
			Handler:         root.handleConfig,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "POST",
			Pattern:         "/config/{serviceName}/port",
			Handler:         root.handlePortUpdate,
			MakeMessage:     func() interface{} { return &common.PortUpdateMessage{} },
			UseRequestToken: false,
		},
	}
	return routes
}

// Run configures and starts root service.
func Run(configFileName string) (*common.RestServiceInfo, error) {
	log.Printf("Entering root.Run()")
	fullConfig, err := common.ReadConfig(configFileName)
	if err != nil {
		return nil, err
	}

	rootService := &Root{}
	log.Printf("Initializing root config with\n%v\nand\n%v", fullConfig.Services["root"].Common, fullConfig)
	rootServiceConfig := common.ServiceConfig{
		Common:          fullConfig.Services["root"].Common,
		ServiceSpecific: make(map[string]interface{}),
	}
	rootServiceConfig.ServiceSpecific[fullConfigKey] = fullConfig
	return common.InitializeService(rootService, rootServiceConfig)
}
