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

package policy

import (
	"errors"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"log"
	//	"net"
)

// Policy provides Policy service.
type PolicySvc struct {
	config common.ServiceConfig
}

const (
	infoListPath = "/info"
)

func (policy *PolicySvc) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:          "POST",
			Pattern:         "/policies",
			Handler:         policy.addPolicy,
			MakeMessage:     func() interface{} { return &common.Policy{} },
			UseRequestToken: false,
		},
		common.Route{
			Method:          "DELETE",
			Pattern:         "/policies/{id}",
			Handler:         policy.deletePolicy,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
	}
	return routes
}

// handleHost handles request for a specific host's info
func (policy *PolicySvc) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policyDoc := input.(*common.Policy)
	log.Printf("Request for a new policy to be added: %v", policyDoc)
	client, err := common.NewRestClient(common.GetRestClientConfig(policy.config))
	if err != nil {
		return nil, err
	}
	// Get host info from topology service
	topoUrl, err := client.GetServiceUrl("topology")
	if err != nil {
		return nil, err
	}

	index := common.IndexResponse{}
	err = client.Get(topoUrl, &index)
	if err != nil {
		return nil, err
	}

	hostsURL := index.Links.FindByRel("host-list")
	var hosts []common.HostMessage

	err = client.Get(hostsURL, &hosts)
	if err != nil {
		return nil, err
	}

	found := false

	tenantSvcUrl, err := client.GetServiceUrl("tenant")
	if err != nil {
		return nil, err
	}

	// TODO follow links once tenant service supports it. For now...

	tenantsUrl := fmt.Sprintf("%s/tenants", tenantSvcUrl)
	var tenants []tenant.Tenant
	err = client.Get(tenantsUrl, &tenants)
	if err != nil {
		return nil, err
	}
	found = false
	var i int
	tenantName := "TODO"
	for i = range tenants {
		if tenants[i].Name == tenantName {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("Tenant with name " + tenantName + " not found")
	}

	segmentsUrl := fmt.Sprintf("/tenants/%s/segments", "")
	var segments []tenant.Segment
	err = client.Get(segmentsUrl, &segments)
	if err != nil {
		return nil, err
	}
	found = false
	segmentName := "TODO"
	for _, s := range segments {
		if s.Name == segmentName {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("Segment with name " + segmentName + " not found")
	}
	return nil, nil
}

func (policy *PolicySvc) deletePolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	// TODO placeholder
//	idStr := ctx.PathVariables["id"]
	return nil, nil
}

// Name provides name of this service.
func (policy *PolicySvc) Name() string {
	return "policy"
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (policy *PolicySvc) SetConfig(config common.ServiceConfig) error {
	// TODO this is a copy-paste of topology service, to refactor
	log.Println(config)
	policy.config = config
	//	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	log.Printf("Policy port: %d", config.Common.Api.Port)
	//	policy.store = policyStore{}
	//	policy.store.ServiceStore = &policy.store
	//	return policy.store.SetConfig(storeConfig)
	return nil

}

func (policy *PolicySvc) createSchema(overwrite bool) error {
	return nil
}

// Run mainly runs IPAM service.
func Run(rootServiceUrl string, cred *common.Credential) (*common.RestServiceInfo, error) {
	clientConfig := common.GetDefaultRestClientConfig(rootServiceUrl)
	clientConfig.Credential = cred
	client, err := common.NewRestClient(clientConfig)
	
	if err != nil {
		return nil, err
	}
	policy := &PolicySvc{}
	config, err := client.GetServiceConfig(policy)
	if err != nil {
		return nil, err
	}
	return common.InitializeService(policy, *config)

}

func (policy *PolicySvc) Initialize() error {
	log.Println("Entering policy.Initialize()")
	//	err := policy.store.Connect()
	//	if err != nil {
	//		return err
	//	}
	return nil
}

// CreateSchema creates schema for Policy service.
func CreateSchema(rootServiceUrl string, overwrite bool) error {
	return nil
}
