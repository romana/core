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
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package tenant

import (
	"log"
	"strconv"

	"github.com/romana/core/common"
)

// TenantSvc provides tenant service.
type TenantSvc struct {
	store  tenantStore
	config common.ServiceConfig
	dc     common.Datacenter
}

const (
	tenantsPath        = "/tenants"
	segmentsPath       = "/segments"
	tenantNameQueryVar = "tenantName"
)

// Routes provides route for tenant service.
func (tsvc *TenantSvc) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:      "POST",
			Pattern:     tenantsPath,
			Handler:     tsvc.addTenant,
			MakeMessage: func() interface{} { return &Tenant{} },
		},
		common.Route{
			Method:  "GET",
			Pattern: tenantsPath + "/{tenantId}",
			Handler: tsvc.getTenant,
		},
		common.Route{
			Method:  "GET",
			Pattern: tenantsPath,
			Handler: tsvc.listTenants,
		},
		common.Route{
			Method:      "POST",
			Pattern:     tenantsPath + "/{tenantId}" + segmentsPath,
			Handler:     tsvc.addSegment,
			MakeMessage: func() interface{} { return &Segment{} },
		},
		common.Route{
			Method:          "GET",
			Pattern:         tenantsPath + "/{tenantId}" + segmentsPath + "/{segmentId}",
			Handler:         tsvc.getSegment,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         tenantsPath + "/{tenantId}" + segmentsPath,
			Handler:         tsvc.listSegments,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
	}
	var t = []Tenant{}
	routes = append(routes, common.CreateFindRoutes(&t, &tsvc.store.DbStore)...)
	var s = []Segment{}
	routes = append(routes, common.CreateFindRoutes(&s, &tsvc.store.DbStore)...)
	return routes
}

// addTenant calls Tenant Service to create a tenant with the
// specific details provided as input. It returns full details
// about the created tenant or HTTP Error.
func (tsvc *TenantSvc) addTenant(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("TenantService: Entering addTenant()")
	newTenant := input.(*Tenant)
	err := tsvc.store.addTenant(newTenant)
	log.Printf("TenantService: Attempting to add tenant %+v: %+v", newTenant, err)
	if err != nil {
		return nil, err
	}
	return newTenant, err
}
func (tsvc *TenantSvc) listTenants(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In listTenants()")
	tenants, err := tsvc.store.listTenants()
	if err != nil {
		return nil, err
	}
	return tenants, nil
}

func (tsvc *TenantSvc) listSegments(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In listSegments()")
	idStr := ctx.PathVariables["tenantId"]
	segments, err := tsvc.store.listSegments(idStr)
	if err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		return nil, common.NewError404("segment", "ALL")
	}
	return segments, nil
}

func (tsvc *TenantSvc) getTenant(input interface{}, ctx common.RestContext) (interface{}, error) {
	idStr := ctx.PathVariables["tenantId"]
	log.Printf("In findTenant(%s)\n", idStr)
	return tsvc.store.getTenant(idStr)
}

func (tsvc *TenantSvc) addSegment(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In addSegment()")
	tenantIdStr := ctx.PathVariables["tenantId"]
	tenantId, err := strconv.ParseUint(tenantIdStr, 10, 64)
	if err != nil {
		return nil, err
	}
	newSegment := input.(*Segment)
	err = tsvc.store.addSegment(tenantId, newSegment)
	return newSegment, err
}

func (tenant *TenantSvc) Name() string {
	return "tenant"
}

func (tsvc *TenantSvc) getSegment(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In findSegment()")
	tenantIdStr := ctx.PathVariables["tenantId"]
	segmentIdStr := ctx.PathVariables["segmentId"]

	return tsvc.store.getSegment(tenantIdStr, segmentIdStr)
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (tsvc *TenantSvc) SetConfig(config common.ServiceConfig) error {
	tsvc.config = config
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	tsvc.store = tenantStore{}
	// TODO
	// From review:
	// What's going on here? Why does ServicStore need a reference to the structure that contains it?
	// Need a good way to document this (pattern or anti-pattern?)
	tsvc.store.ServiceStore = &tsvc.store
	return tsvc.store.SetConfig(storeConfig)
}

func (tsvc *TenantSvc) createSchema(overwrite bool) error {
	return tsvc.store.CreateSchema(overwrite)
}

// Run configures and runs tenant service.
func Run(rootServiceUrl string, cred *common.Credential) (*common.RestServiceInfo, error) {
	tsvc := &TenantSvc{}
	clientConfig := common.GetDefaultRestClientConfig(rootServiceUrl)
	clientConfig.Credential = cred
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		return nil, err
	}
	config, err := client.GetServiceConfig(tsvc.Name())
	if err != nil {
		return nil, err
	}
	return common.InitializeService(tsvc, *config)

}

func (tsvc *TenantSvc) Initialize() error {
	err := tsvc.store.Connect()
	if err != nil {
		return err
	}

	client, err := common.NewRestClient(common.GetRestClientConfig(tsvc.config))
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl("topology")
	if err != nil {
		return err
	}

	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return err
	}

	dcURL := index.Links.FindByRel("datacenter")
	dc := common.Datacenter{}
	err = client.Get(dcURL, &dc)
	if err != nil {
		return err
	}
	// TODO should this always be queried?
	tsvc.dc = dc
	return nil
}

// CreateSchema runs topology service.
func CreateSchema(rootServiceUrl string, overwrite bool) error {
	log.Println("In CreateSchema(", rootServiceUrl, ",", overwrite, ")")
	tsvc := &TenantSvc{}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootServiceUrl))
	if err != nil {
		return err
	}

	config, err := client.GetServiceConfig(tsvc.Name())
	if err != nil {
		return err
	}

	err = tsvc.SetConfig(*config)
	if err != nil {
		return err
	}
	return tsvc.store.CreateSchema(overwrite)
}
