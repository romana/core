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
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/store"
)

// PolicySvc provides Policy service.
type PolicySvc struct {
	client *common.RestClient
	config common.ServiceConfig
	store  policyStore
	sync.RWMutex
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
	if endpoint.Peer == common.Wildcard {
		// If a wildcard is specfied, there is nothing to augment
		return nil
	}
	log.Printf("Policy: Augmenting  %#v", endpoint)

	// Code below tries to resolve tenant name into tenant_network_id if possible.
	//
	// TODO this will have to be changed once we implement
	// https://paninetworks.kanbanize.com/ctrl_board/3/cards/319/details
	ten := &common.Tenant{}
	if endpoint.TenantNetworkID == nil {
		if endpoint.TenantID != 0 {
			tenantIDToUse := strconv.FormatUint(endpoint.TenantID, 10)
			tenantsUrl := fmt.Sprintf("%s/tenants/%s", tenantSvcUrl, tenantIDToUse)
			log.Printf("Policy: Looking tenant up at %s", tenantsUrl)
			err = policy.client.Get(tenantsUrl, ten)
			if err != nil {
				return err
			}

			endpoint.TenantNetworkID = &ten.NetworkID

		} else if endpoint.TenantExternalID != "" || endpoint.TenantName != "" {
			if endpoint.TenantExternalID != "" {
				ten.ExternalID = endpoint.TenantExternalID
			}
			if endpoint.TenantName != "" {
				ten.Name = endpoint.TenantName
			}
			err = policy.client.Find(ten, common.FindLast)
			if err != nil {
				return err
			}

			endpoint.TenantNetworkID = &ten.NetworkID
		}
	}

	if endpoint.SegmentNetworkID == nil {
		if ten == nil && (endpoint.SegmentID != 0 || endpoint.SegmentExternalID != "" || endpoint.SegmentName != "") {
			return common.NewError400("No tenant information specified, cannot look up segment.")
		}
		segment := &common.Segment{}
		if endpoint.SegmentID != 0 {
			segmentIDToUse := strconv.FormatUint(endpoint.SegmentID, 10)
			segmentsUrl := fmt.Sprintf("%s/tenants/%d/segments/%s", tenantSvcUrl, ten.ID, segmentIDToUse)
			log.Printf("Policy: Looking segment up at %s for %#v", segmentsUrl, endpoint)
			err = policy.client.Get(segmentsUrl, &segment)
			if err != nil {
				return err
			}
			endpoint.SegmentNetworkID = &segment.NetworkID
		} else if endpoint.SegmentExternalID != "" || endpoint.SegmentName != "" {
			segmentsUrl := fmt.Sprintf("%s/findLast/segments?tenant_id=%d&", tenantSvcUrl, ten.ID)
			if endpoint.SegmentExternalID != "" {
				segmentsUrl += "external_id=" + endpoint.TenantExternalID + "&"
			}
			if endpoint.SegmentName != "" {
				segmentsUrl += "name=" + endpoint.SegmentName
			}
			log.Printf("Policy: Finding segments at %s for %#v (Tenant %#v %t)", segmentsUrl, endpoint, ten, ten == nil)
			err = policy.client.Get(segmentsUrl, &segment)
			if err != nil {
				return err
			}
			endpoint.SegmentNetworkID = &segment.NetworkID
		}
	}
	return nil
}

// augmentPolicy augments the provided policy with information gotten from
// various services.
func (policy *PolicySvc) augmentPolicy(policyDoc *common.Policy) error {
	// Get info from topology service
	log.Printf("Augmenting policy %s", policyDoc.Name)

	if policyDoc.ExternalID != "" {
		// TODO
		// Important! This should really be done in policy agent.
		// Only done here as temporary measure.
		externalId := makeId(policyDoc.AppliedTo, policyDoc.Name)
		log.Printf("Constructing internal policy name = %s", externalId)
		policyDoc.ExternalID = externalId
	}

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
	dc := &common.Datacenter{}
	err = policy.client.Get(dcURL, dc)
	if err != nil {
		return err
	}
	log.Printf("Policy server received datacenter information from topology service: %+v\n", dc)
	policyDoc.Datacenter = dc

	for i, _ := range policyDoc.AppliedTo {
		endpoint := &policyDoc.AppliedTo[i]
		err = policy.augmentEndpoint(endpoint)
		if err != nil {
			return err
		}
	}

	for j, _ := range policyDoc.Ingress {
		for i, _ := range policyDoc.Ingress[j].Rules {
			rule := &policyDoc.Ingress[j].Rules[i]
			rule.Protocol = strings.ToUpper(rule.Protocol)
		}

		for i, _ := range policyDoc.Ingress[j].Peers {
			endpoint := &policyDoc.Ingress[j].Peers[i]
			err = policy.augmentEndpoint(endpoint)
			if err != nil {
				return err
			}
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
		err = policy.client.Post(url, policyDoc, &result)
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
	policy.RLock()
	defer policy.RUnlock()

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
	policy.Lock()
	defer policy.Unlock()

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
		log.Printf("IN deletePolicyHandler with %v", policyDoc)
		id, err := policy.store.lookupPolicy(policyDoc.ExternalID)

		if err != nil {
			// TODO
			// Important! This should really be done in policy agent.
			// Only done here as temporary measure.
			externalId := makeId(policyDoc.AppliedTo, policyDoc.Name)
			log.Printf("Constructing internal policy name = %s", externalId)
			policyDoc.ExternalID = externalId

			id, err = policy.store.lookupPolicy(policyDoc.ExternalID)
		}

		log.Printf("Found %d / %v (%T) from external ID %s", id, err, err, policyDoc.ExternalID)
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

	err = policy.store.deletePolicy(id)
	if err != nil {
		return nil, err
	}
	policyDoc.Datacenter = nil
	return policyDoc, nil
}

// listPolicies lists all policices.
func (policy *PolicySvc) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
	policy.RLock()
	defer policy.RUnlock()

	policies, err := policy.store.listPolicies()
	if err != nil {
		return nil, err
	}
	for i, _ := range policies {
		policies[i].Datacenter = nil
	}
	return policies, nil
}

// findPolicyByName returns the first policy found corresponding
// to the given policy name. Policy names are not unique unlike
// policy ID's.
func (policy *PolicySvc) findPolicyByName(input interface{}, ctx common.RestContext) (interface{}, error) {
	policy.RLock()
	defer policy.RUnlock()

	nameStr := ctx.PathVariables["policyName"]
	log.Printf("In findPolicy(%s)\n", nameStr)
	if nameStr == "" {
		return nil, common.NewError500(fmt.Sprintf("Expected policy name, got %s", nameStr))
	}
	policyDoc, err := policy.store.findPolicyByName(nameStr)
	if err != nil {
		return nil, err
	}
	policyDoc.Datacenter = nil
	return policyDoc, nil
}

// addPolicy stores the new policy and sends it to all agents.
func (policy *PolicySvc) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policy.Lock()
	defer policy.Unlock()

	policyDoc := input.(*common.Policy)
	log.Printf("addPolicy(): Request for a new policy to be added: %s", policyDoc.Name)
	err := policyDoc.Validate()
	if err != nil {
		log.Printf("addPolicy(): Error validating: %v", err)
		return nil, err
	}

	log.Printf("addPolicy(): Request for a new policy to be added: %v", policyDoc)

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
	policyDoc.Datacenter = nil
	return policyDoc, nil
}

// Name provides name of this service.
func (policy *PolicySvc) Name() string {
	return "policy"
}

// SetConfig implements SetConfig function of the Service interface.
// Returns an error if cannot connect to the data store
func (policy *PolicySvc) SetConfig(config common.ServiceConfig) error {
	policy.Lock()
	defer policy.Unlock()

	// TODO this is a copy-paste of topology service, to refactor
	log.Println(config)
	policy.config = config
	storeConfigMap := config.ServiceSpecific["store"].(map[string]interface{})
	rdbmsStore, err := store.GetStore(storeConfigMap)
	if err != nil {
		return err
	}
	policy.store.RdbmsStore = rdbmsStore.(*store.RdbmsStore)
	policy.store.ServiceStore = &policy.store
	return nil
}

func (policy *PolicySvc) CreateSchema(overwrite bool) error {
	policy.Lock()
	defer policy.Unlock()

	return policy.store.CreateSchema(overwrite)
}

func (policy *PolicySvc) Initialize(client *common.RestClient) error {
	policy.Lock()
	defer policy.Unlock()

	log.Println("Entering policy.Initialize()")
	err := policy.store.Connect()
	if err != nil {
		return err
	}
	policy.client = client
	return nil
}

// makeId generates uniq id from applied to field.
func makeId(allowedTo []common.Endpoint, name string) string {
	var data string
	data = name

	for _, e := range allowedTo {
		if data == "" {
			data = fmt.Sprintf("%s", e)
		} else {
			data = fmt.Sprintf("%s\n%s", data, e)
		}
	}

	hasher := sha1.New()
	hasher.Write([]byte(data))
	sum := hasher.Sum(nil)

	// Taking 6 bytes of a hash which is 12 chars length
	return fmt.Sprint(hex.EncodeToString(sum[:6]))
}
