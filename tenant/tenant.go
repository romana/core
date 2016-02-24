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
	"github.com/romana/core/common"
	"log"
	"strconv"
)

// TenantSvc provides tenant service.
type TenantSvc struct {
	config common.ServiceConfig
	store  tenantStore
	dc     common.Datacenter
}

const (
	tenantsPath  = "/tenants"
	segmentsPath = "/segments"
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
			Method:      "GET",
			Pattern:     tenantsPath + "/{tenantId}",
			Handler:     tsvc.findTenant,
			MakeMessage: nil,
		},
		common.Route{
			Method:      "GET",
			Pattern:     tenantsPath,
			Handler:     tsvc.listTenants,
			MakeMessage: nil,
		},
		common.Route{
			Method:      "POST",
			Pattern:     tenantsPath + "/{tenantId}" + segmentsPath,
			Handler:     tsvc.addSegment,
			MakeMessage: func() interface{} { return &Segment{} },
		},
		common.Route{
			Method:      "GET",
			Pattern:     tenantsPath + "/{tenantId}" + segmentsPath + "/{segmentId}",
			Handler:     tsvc.findSegment,
			MakeMessage: nil,
		},
		common.Route{
			Method:      "GET",
			Pattern:     tenantsPath + "/{tenantId}" + segmentsPath,
			Handler:     tsvc.listSegments,
			MakeMessage: nil,
		},
	}
	return routes
}

func (tsvc *TenantSvc) addTenant(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In addTenant()")
	newTenant := input.(*Tenant)
	err := tsvc.store.addTenant(newTenant)

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
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	segments, err := tsvc.store.listSegments(id)
	if err != nil {
		return nil, err
	}
	return segments, nil
}

func (tsvc *TenantSvc) findTenant(input interface{}, ctx common.RestContext) (interface{}, error) {
	idStr := ctx.PathVariables["tenantId"]
	log.Printf("In findTenant(%s)\n", idStr)
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, err
	}
	tenant, err := tsvc.store.findTenant(id)
	if err != nil {
		return nil, err
	}
	return tenant, nil
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

func (tsvc *TenantSvc) findSegment(input interface{}, ctx common.RestContext) (interface{}, error) {
	log.Println("In findSegment()")
	tenantIdStr := ctx.PathVariables["tenantId"]
	tenantId, err := strconv.ParseUint(tenantIdStr, 10, 64)

	if err != nil {
		return nil, err
	}
	segmentIdStr := ctx.PathVariables["segmentId"]

	segmentId, err := strconv.ParseUint(segmentIdStr, 10, 64)

	if err != nil {
		return nil, err
	}

	segment, err := tsvc.store.findSegment(tenantId, segmentId)
	if err != nil {
		return nil, err
	}
	return segment, nil
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (tsvc *TenantSvc) SetConfig(config common.ServiceConfig) error {
	log.Println(config)
	tsvc.config = config
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	tsvc.store = tenantStore{}
	tsvc.store.ServiceStore = tsvc.store
	return tsvc.store.SetConfig(storeConfig)
}

func (tsvc *TenantSvc) createSchema(overwrite bool) error {
	return tsvc.store.CreateSchema(overwrite)
}

// Run configures and runs tenant service.
func Run(rootServiceUrl string) (chan common.ServiceMessage, string, error) {
	tsvc := &TenantSvc{}
	client, err := common.NewRestClient(rootServiceUrl, common.DefaultRestTimeout)
	if err != nil {
		return nil, "", err
	}
	config, err := client.GetServiceConfig(rootServiceUrl, tsvc)
	if err != nil {
		return nil, "", err
	}
	return common.InitializeService(tsvc, *config)

}

func (tsvc *TenantSvc) Initialize() error {
	err := tsvc.store.Connect()
	if err != nil {
		return err
	}

	client, err := common.NewRestClient("", tsvc.config.Common.Api.RestTimeoutMillis)
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl(tsvc.config.Common.Api.RootServiceUrl, "topology")
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

	client, err := common.NewRestClient("", common.DefaultRestTimeout)
	if err != nil {
		return err
	}

	config, err := client.GetServiceConfig(rootServiceUrl, tsvc)
	if err != nil {
		return err
	}

	err = tsvc.SetConfig(*config)
	if err != nil {
		return err
	}
	return tsvc.store.CreateSchema(overwrite)
}
