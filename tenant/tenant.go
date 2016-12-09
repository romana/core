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
	"github.com/romana/core/common/store"
	log "github.com/romana/rlog"
	"strconv"
)

// TenantSvc provides tenant service.
type TenantSvc struct {
	store  tenantStore
	config common.ServiceConfig
	dc     common.Datacenter
	client *common.RestClient
}

const (
	tenantsPath        = "/tenants"
	segmentsPath       = "/segments"
	tenantNameQueryVar = "tenantName"
)

// TenantIDChecker implements AuthZChecker function, ensuring that
// only user that has attribute of tenant corresponding to the
// tenantId in the path of request is allowed to execute.
func TenantIDChecker(ctx common.RestContext) bool {
	idStr := ctx.PathVariables["tenantId"]
	u := ctx.User
	for _, role := range u.Roles {
		if role.Name == common.RoleAdmin || role.Name == common.RoleService {
			return true
		}
	}
	for _, role := range u.Roles {
		if role.Name == common.RoleTenant {
			for _, attr := range u.Attributes {
				if attr.AttributeKey == "tenant" && attr.AttributeValue == idStr {
					return true
				}
			}
		}
	}
	return false
}

// Routes provides route for tenant service.
func (tsvc *TenantSvc) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:      "POST",
			Pattern:     tenantsPath,
			Handler:     tsvc.addTenant,
			MakeMessage: func() interface{} { return &common.Tenant{} },
		},
		common.Route{
			Method:       "GET",
			Pattern:      tenantsPath + "/{tenantId}",
			Handler:      tsvc.getTenant,
			AuthZChecker: TenantIDChecker,
		},
		common.Route{
			Method:  "GET",
			Pattern: tenantsPath,
			Handler: tsvc.listTenants,
		},
		common.Route{
			Method:       "POST",
			Pattern:      tenantsPath + "/{tenantId}" + segmentsPath,
			Handler:      tsvc.addSegment,
			MakeMessage:  func() interface{} { return &common.Segment{} },
			AuthZChecker: TenantIDChecker,
		},
		common.Route{
			Method:          "GET",
			Pattern:         tenantsPath + "/{tenantId}" + segmentsPath + "/{segmentId}",
			Handler:         tsvc.getSegment,
			MakeMessage:     nil,
			UseRequestToken: false,
			AuthZChecker:    TenantIDChecker,
		},
		common.Route{
			Method:          "GET",
			Pattern:         tenantsPath + "/{tenantId}" + segmentsPath,
			Handler:         tsvc.listSegments,
			MakeMessage:     nil,
			UseRequestToken: false,
			AuthZChecker:    TenantIDChecker,
		},
	}
	var t = []common.Tenant{}
	routes = append(routes, common.CreateFindRoutes(&t, &tsvc.store)...)
	var s = []common.Segment{}
	routes = append(routes, common.CreateFindRoutes(&s, &tsvc.store)...)
	return routes
}

// addTenant calls Tenant Service to create a tenant with the
// specific details provided as input. It returns full details
// about the created tenant or HTTP Error.
func (tsvc *TenantSvc) addTenant(input interface{}, ctx common.RestContext) (interface{}, error) {
	newTenant := input.(*common.Tenant)
	err := tsvc.store.addTenant(newTenant)
	if err != nil {
		log.Printf("TenantService: Attempting to add tenant %+v: %+v", newTenant, err)
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
	newSegment := input.(*common.Segment)
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
	var err error
	tsvc.config = config
	storeConfigMap := config.ServiceSpecific["store"].(map[string]interface{})
	rdbmsStore, err := store.GetStore(storeConfigMap)
	if err != nil {
		return err
	}
	tsvc.store.RdbmsStore = rdbmsStore.(*store.RdbmsStore)
	tsvc.store.ServiceStore = &tsvc.store
	return nil
}

func (tsvc *TenantSvc) CreateSchema(overwrite bool) error {
	return tsvc.store.CreateSchema(overwrite)
}

func (tsvc *TenantSvc) Initialize(client *common.RestClient) error {
	err := tsvc.store.Connect()
	if err != nil {
		return err
	}

	tsvc.client = client
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
