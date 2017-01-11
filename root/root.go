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
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/romana/core/common"
	log "github.com/romana/rlog"
	"io/ioutil"
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
	privateKey *rsa.PrivateKey
	publicKey  []byte
	store      rootStore
}

// SetConfig implements SetConfig function of the Service interface
func (root *Root) SetConfig(config common.ServiceConfig) error {
	log.Printf("Entering root.SetConfig()")
	root.config = Config{}
	root.config.common = &config.Common
	f := config.ServiceSpecific[common.FullConfigKey].(common.Config)
	root.config.full = &f
	var err error
	rootConfig := root.config.full.Services[root.Name()].ServiceSpecific

	root.store = rootStore{}
	root.store.ServiceStore = &root.store
	storeConfigMap := rootConfig["store"].(map[string]interface{})
	storeConfig, err := common.MakeStoreConfig(storeConfigMap)
	if err != nil {
		return err
	}
	err = root.store.SetConfig(storeConfig)
	if err != nil {
		return err
	}

	auth, err := common.ToBool(rootConfig["auth"])
	if err != nil {
		return err
	}

	root.store.isAuthEnabled = auth

	log.Debugf("Checking auth: %t", root.store.isAuthEnabled)

	if root.store.isAuthEnabled {
		log.Infof("Auth is on!\n")
		privateKeyLocation := rootConfig["auth_private"].(string)
		log.Infof("Reading private key from %s", privateKeyLocation)
		data, err := ioutil.ReadFile(privateKeyLocation)
		if err != nil {
			return err
		}
		root.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(data)
		if err != nil {
			return err
		}
		publicKeyLocation := config.Common.Api.AuthPublic
		log.Debugf("Reading public key from %s", publicKeyLocation)
		root.publicKey, err = ioutil.ReadFile(publicKeyLocation)
		if err != nil {
			return err
		}
		log.Infof("Read public key: %s", string(root.publicKey))
		storeConfigMap := rootConfig["store"].(map[string]interface{})
		storeConfig, err := common.MakeStoreConfig(storeConfigMap)
		if err != nil {
			return err
		}
		return root.store.SetConfig(storeConfig)
	} else {
		root.publicKey = []byte{}
	}
	return nil
}

func (root *Root) Initialize(client *common.RestClient) error {
	return root.store.Connect()
}

// handlePortUpdate updates the Root service's information with real port
// a service listens on (if it was started with anonymous port 0).
// See https://github.com/romanaproject/romana/wiki/Root-service-API
func (root *Root) handlePortUpdate(input interface{}, ctx common.RestContext) (interface{}, error) {
	pathVars := ctx.PathVariables
	serviceName := pathVars["serviceName"]
	log.Printf("RootService.handlePortUpdate: For service %s got %+v\n", serviceName, input)
	if input == nil {
		return nil, common.NewError400("Port update message expected, received nothing")
	}
	portUpdateMsg := input.(*common.PortUpdateMessage)
	serviceConfig := root.config.full.Services[serviceName]
	oldPort := serviceConfig.Common.Api.Port
	serviceConfig.Common.Api.Port = portUpdateMsg.Port
	log.Infof("RootService: registering port %d for service %s (was %d)\n", serviceConfig.Common.Api.Port, serviceName, oldPort)
	return nil, nil
}

// handleKey handles /publicKey URL - serving the public key of the server.
func (root *Root) handleKey(input interface{}, ctx common.RestContext) (interface{}, error) {
	return root.publicKey, nil
}

// Handler for the /auth URL
func (root *Root) handleAuth(input interface{}, ctx common.RestContext) (interface{}, error) {
	cred := input.(*common.Credential)
	// We assume just username/password for now
	user, err := root.store.Authenticate(*cred)
	if err != nil {
		return nil, err
	}
	// TODO make this configurable?
	user.ExpiresAt = time.Now().Add(time.Second * 3600 * 24).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, user)
	jwtString, err := token.SignedString(root.privateKey)
	log.Printf("Signed token %v as %s", token, jwtString)
	return common.AuthTokenMessage{Token: jwtString}, err
}

// handleIndex is a handler for the / URL
// See https://github.com/romanaproject/romana/wiki/Root-service-API
func (root *Root) handleIndex(input interface{}, ctx common.RestContext) (interface{}, error) {
	retval := common.RootIndexResponse{}

	retval.ServiceName = common.ServiceNameRoot
	myUrl := strings.Join([]string{"http://", root.config.common.Api.Host, ":", strconv.FormatUint(root.config.common.Api.Port, 10)}, "")

	// Links has links to config URLs for now, but also one for self, one for auth
	// and one for the key - hence plus 3
	retval.Links = make([]common.LinkResponse, len(root.config.full.Services)+3)

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
	i++
	retval.Links[i] = common.LinkResponse{Href: "/publicKey", Rel: "publicKey"}
	return retval, nil
}

func (root *Root) Name() string {
	return common.ServiceNameRoot
}

func (root *Root) CreateSchema(o bool) error {
	return root.store.CreateSchema(o)
}

// Handler for the /config
func (root *Root) handleConfig(input interface{}, ctx common.RestContext) (interface{}, error) {
	pathVars := ctx.PathVariables
	serviceName := pathVars["serviceName"]
	log.Printf("Received request for config of %s", serviceName)
	retval := root.config.full.Services[serviceName]
	return retval, nil
}

// Routes provided by root service.
func (root *Root) Routes() common.Routes {
	authRoute := common.Route{
		Method:          "POST",
		Pattern:         common.AuthPath,
		Handler:         root.handleAuth,
		MakeMessage:     func() interface{} { return &common.Credential{} },
		UseRequestToken: false,
	}
	keyRoute := common.Route{
		Method:          "GET",
		Pattern:         "/publicKey",
		Handler:         root.handleKey,
		MakeMessage:     nil,
		UseRequestToken: false,
	}
	routes := common.Routes{
		common.Route{
			Method:          "GET",
			Pattern:         "/",
			Handler:         root.handleIndex,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		authRoute,
		keyRoute,
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

func CreateSchema(configFileName string, overwrite bool) error {
	log.Infof("Entering root.CreateSchema()")
	fullConfig, err := common.ReadConfig(configFileName)
	if err != nil {
		return err
	}

	rootService := &Root{}
	rootServiceConfig := common.ServiceConfig{
		Common:          fullConfig.Services[common.ServiceNameRoot].Common,
		ServiceSpecific: make(map[string]interface{}),
	}
	rootServiceConfig.ServiceSpecific[common.FullConfigKey] = fullConfig
	rootService.SetConfig(rootServiceConfig)
	return rootService.CreateSchema(overwrite)
}

// Run configures and starts root service.
func Run(configFileName string) (*common.RestServiceInfo, error) {
	log.Printf("Entering root.Run()")
	fullConfig, err := common.ReadConfig(configFileName)
	if err != nil {
		return nil, err
	}

	rootService := &Root{}
	log.Printf("Initializing root config")
	rootServiceConfig := common.ServiceConfig{
		Common:          fullConfig.Services[common.ServiceNameRoot].Common,
		ServiceSpecific: make(map[string]interface{}),
	}
	rootServiceConfig.ServiceSpecific[common.FullConfigKey] = fullConfig
	return common.InitializeService(rootService, rootServiceConfig, nil)
}
