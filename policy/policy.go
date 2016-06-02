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

package policy

import (
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"log"
	"strconv"
	"strings"
)

// Policy provides Policy service.
type PolicySvc struct {
	client *common.RestClient
	config common.ServiceConfig
	store  policyStore
}

const (
	infoListPath       = "/info"
	findPath           = "/find"
	policiesPath       = "/policies"
	policyNameQueryVar = "policyName"
)

func (policy *PolicySvc) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			Method:          "POST",
			Pattern:         policiesPath,
			Handler:         policy.addPolicy,
			MakeMessage:     func() interface{} { return &common.Policy{} },
			UseRequestToken: false,
		},
		common.Route{
			Method:          "DELETE",
			Pattern:         policiesPath,
			Handler:         policy.deletePolicyHandler,
			MakeMessage:     func() interface{} { return &common.Policy{} },
			UseRequestToken: false,
		},
		common.Route{
			Method:          "DELETE",
			Pattern:         policiesPath + "/{policyID}",
			Handler:         policy.deletePolicyHandler,
			MakeMessage:     func() interface{} { return &common.Policy{} },
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         policiesPath,
			Handler:         policy.listPolicies,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:          "GET",
			Pattern:         policiesPath + "/{policyID}",
			Handler:         policy.getPolicy,
			MakeMessage:     nil,
			UseRequestToken: false,
		},
		common.Route{
			Method:  "GET",
			Pattern: findPath + policiesPath + "/{policyName}",
			Handler: policy.findPolicyByName,
		},
	}
	return routes
}

// augmentEndpoint augments the endpoint provided with appropriate information
// by looking it up in the appropriate service.
func (policy *PolicySvc) augmentEndpoint(endpoint *common.Endpoint) error {
	tenantSvcUrl, err := policy.client.GetServiceUrl("tenant")
	if err != nil {
		return err
	}

	// TODO this will have to be changed once we implement
	// https://paninetworks.kanbanize.com/ctrl_board/3/cards/319/details
	var tenantIDToUse string
	ten := &tenant.Tenant{}
	if endpoint.TenantID != 0 {
		tenantIDToUse = strconv.FormatUint(endpoint.TenantID, 10)
	} else if endpoint.TenantExternalID != "" {
		tenantIDToUse = endpoint.TenantExternalID
	}
	if tenantIDToUse != "" {
		tenantsUrl := fmt.Sprintf("%s/tenants/%s", tenantSvcUrl, tenantIDToUse)
		err = policy.client.Get(tenantsUrl, &ten)
		if err != nil {
			return err
		}
		endpoint.TenantNetworkID = &ten.Seq
		log.Printf("Net ID from %s: %d", tenantsUrl, *endpoint.TenantNetworkID)
	}

	var segmentIDToUse string
	if endpoint.SegmentID != 0 {
		segmentIDToUse = strconv.FormatUint(endpoint.SegmentID, 10)
	} else if endpoint.SegmentExternalID != "" {
		segmentIDToUse = endpoint.SegmentExternalID
	}
	if segmentIDToUse != "" {
		tenantsUrl := fmt.Sprintf("%s/tenants/%d/segments/%s", tenantSvcUrl, ten.ID, segmentIDToUse)
		segment := &tenant.Segment{}
		err = policy.client.Get(tenantsUrl, &segment)
		if err != nil {
			return err
		}
		endpoint.SegmentNetworkID = &segment.Seq
		log.Printf("Net ID from %s: %d", tenantsUrl, *endpoint.SegmentNetworkID)
	}

	return nil
}

// augmentPolicy augments the provided policy with information gotten from
// various services.
func (policy *PolicySvc) augmentPolicy(policyDoc *common.Policy) error {
	// Get info from topology service
	topoUrl, err := policy.client.GetServiceUrl("topology")
	if err != nil {
		return err
	}

	// Query topology for data center information
	// TODO move this to root
	index := common.IndexResponse{}
	err = policy.client.Get(topoUrl, &index)
	if err != nil {
		return err
	}

	dcURL := index.Links.FindByRel("datacenter")
	dc := common.Datacenter{}
	err = policy.client.Get(dcURL, &dc)
	if err != nil {
		return err
	}
	log.Printf("Policy server received datacenter information from topology service: %s\n", dc)
	policyDoc.Datacenter = dc

	for i, _ := range policyDoc.Rules {
		rule := &policyDoc.Rules[i]
		rule.Protocol = strings.ToUpper(rule.Protocol)
	}

	for i, _ := range policyDoc.AppliedTo {
		endpoint := &policyDoc.AppliedTo[i]
		err = policy.augmentEndpoint(endpoint)
		if err != nil {
			return err
		}
	}

	for i, _ := range policyDoc.Peers {
		endpoint := &policyDoc.Peers[i]
		err = policy.augmentEndpoint(endpoint)
		if err != nil {
			return err
		}
	}
	return nil
}

// distributePolicy distributes policy to all agents.
// TODO how should error handling work here really?
func (policy *PolicySvc) distributePolicy(policyDoc *common.Policy) error {
	hosts, err := policy.client.ListHosts()
	if err != nil {
		return err
	}
	errStr := make([]string, 0)
	for _, host := range hosts {
		// TODO make schema configurable
		url := fmt.Sprintf("http://%s:%d/policies", host.Ip, host.AgentPort)
		log.Printf("Sending policy %s to agent at %s", policyDoc.Name, url)
		result := make(map[string]interface{})
		err = policy.client.Post(url, policyDoc, result)
		log.Printf("Agent at %s returned %v", host.Ip, result)
		if err != nil {
			errStr = append(errStr, fmt.Sprintf("Error applying policy %d to host %s: %v. ", policyDoc.ID, host.Ip, err))
		}
	}
	if len(errStr) > 0 {
		return common.NewError500(errStr)
	}
	return nil
}

func (policy *PolicySvc) getPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	idStr := ctx.PathVariables["policyID"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, common.NewError404("policy", idStr)
	}
	policyDoc, err := policy.store.getPolicy(id, false)
	log.Printf("Found policy for ID %d: %s (%v)", id, policyDoc, err)
	return policyDoc, err
}

func (policy *PolicySvc) deletePolicyHandler(input interface{}, ctx common.RestContext) (interface{}, error) {
	idStr := strings.TrimSpace(ctx.PathVariables["policyID"])
	if idStr == "" {
		if input == nil {
			return nil, common.NewError400("Request must either be to /policies/{policyID} or have a body.")
		}
		policyDoc := input.(*common.Policy)
		err := policyDoc.Validate()
		if err != nil {
			return nil, err
		}
		id, err := policy.store.lookupPolicy(policyDoc.ExternalID, policyDoc.Datacenter.Id)
		log.Printf("Found %d from external ID %s", id, policyDoc.ExternalID)
		if err != nil {
			return nil, err
		}
		return policy.deletePolicy(id)
	} else {
		if input != nil {
			common.NewError400("Request must either be to /policies/{policyID} or have a body.")
		}
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			return nil, common.NewError404("policy", idStr)
		}
		return policy.deletePolicy(id)
	}
}

// deletePolicy deletes policy based the following algorithm:
//1. Mark the policy as "deleted" in the backend store.
func (policy *PolicySvc) deletePolicy(id uint64) (interface{}, error) {
	// TODO do we need this to be transactional or not ... case can be made for either.
	err := policy.store.inactivatePolicy(id)
	if err != nil {
		return nil, err
	}
	policyDoc, err := policy.store.getPolicy(id, true)
	log.Printf("Found policy for ID %d: %s (%v)", id, policyDoc, err)
	if err != nil {
		return nil, err
	}
	hosts, err := policy.client.ListHosts()
	if err != nil {
		return nil, err
	}
	errStr := make([]string, 0)
	for _, host := range hosts {
		// TODO make schema configurable
		url := fmt.Sprintf("http://%s:%d/policies", host.Ip, host.AgentPort)
		result := make(map[string]interface{})
		err = policy.client.Delete(url, policyDoc, result)
		log.Printf("Agent at %s returned %v", host.Ip, result)
		if err != nil {
			errStr = append(errStr, fmt.Sprintf("Error deleting policy %d (%s) from host %s: %v. ", id, policyDoc.Name, host.Ip, err))
		}
	}
	if len(errStr) > 0 {
		return nil, common.NewError500(errStr)
	}
	err = policy.store.deletePolicy(id)
	if err != nil {
		return nil, err
	}
	return policyDoc, nil
}

// deletePolicy deletes policy...
func (policy *PolicySvc) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
	return policy.store.listPolicies()
}

// findPolicyByName returns the first policy found corresponding
// to the given policy name. Policy names are not unique unlike
// policy ID's.
func (policy *PolicySvc) findPolicyByName(input interface{}, ctx common.RestContext) (interface{}, error) {
	nameStr := ctx.PathVariables["policyName"]
	log.Printf("In findPolicy(%s)\n", nameStr)
	if nameStr == "" {
		return nil, common.NewError("Expected policy name, got %s", nameStr)
	}

	policies, err := policy.store.findPolicyByName(nameStr)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

// addPolicy stores the new policy and sends it to all agents.
func (policy *PolicySvc) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policyDoc := input.(*common.Policy)
	log.Printf("addPolicy(): Request for a new policy to be added: %s", policyDoc.Name)
	err := policyDoc.Validate()
	if err != nil {
		log.Printf("addPolicy(): Error validating: %v", err)
		return nil, err
	}

	err = policy.augmentPolicy(policyDoc)
	if err != nil {
		log.Printf("addPolicy(): Error augmenting: %v", err)
		return nil, err
	}
	// Save it
	err = policy.store.addPolicy(policyDoc)
	if err != nil {
		log.Printf("addPolicy(): Error storing: %v", err)
		return nil, err
	}
	log.Printf("addPolicy(): Stored policy %s", policyDoc.Name)
	err = policy.distributePolicy(policyDoc)
	if err != nil {
		log.Printf("addPolicy(): Error distributing: %v", err)
		return nil, err
	}
	return policyDoc, nil
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
	policy.store = policyStore{}
	storeConfig := config.ServiceSpecific["store"].(map[string]interface{})
	policy.store.ServiceStore = &policy.store
	return policy.store.SetConfig(storeConfig)
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
	policy := &PolicySvc{client: client}
	config, err := client.GetServiceConfig(policy.Name())
	if err != nil {
		return nil, err
	}
	return common.InitializeService(policy, *config)

}

func (policy *PolicySvc) Initialize() error {
	log.Println("Entering policy.Initialize()")
	err := policy.store.Connect()
	if err != nil {
		return err
	}
	return nil
}

// CreateSchema creates schema for Policy service.
func CreateSchema(rootServiceURL string, overwrite bool) error {
	log.Println("In CreateSchema(", rootServiceURL, ",", overwrite, ")")
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootServiceURL))
	if err != nil {
		return err
	}

	policySvc := &PolicySvc{}
	config, err := client.GetServiceConfig(policySvc.Name())
	if err != nil {
		return err
	}

	err = policySvc.SetConfig(*config)
	if err != nil {
		return err
	}
	return policySvc.store.CreateSchema(overwrite)
}
