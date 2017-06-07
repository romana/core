// Copyright (c) 2017 Pani Networks
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

package server

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/romana/core/common"
)

const (
	infoListPath       = "/info"
	findPath           = "/find"
	policiesPath       = "/policies"
	policyNameQueryVar = "policyName"
)

func (r *Romanad) normalizePolicy(policyDoc *common.Policy) error {
	for j, _ := range policyDoc.Ingress {
		for i, _ := range policyDoc.Ingress[j].Rules {
			rule := &policyDoc.Ingress[j].Rules[i]
			rule.Protocol = strings.ToUpper(rule.Protocol)
		}
	}
	return nil
}

// distributePolicy distributes policy to all agents.
// TODO how should error handling work here really?
func (r *Romanad) distributePolicy(policyDoc *common.Policy) error {

	// TODO this is temporary before we merge services
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

func (r *Romanad) getPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	idStr := ctx.PathVariables["policyID"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, common.NewError404("policy", idStr)
	}
	policyDoc, err := policy.store.getPolicy(id, false)
	log.Printf("Found policy for ID %d: %s (%v)", id, policyDoc, err)
	return policyDoc, err
}

func (r *Romanad) deletePolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
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

// listPolicies lists all policices.
func (r *Romanad) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
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
func (r *Romanad) findPolicyByName(input interface{}, ctx common.RestContext) (interface{}, error) {
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
func (r *Romanad) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
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
