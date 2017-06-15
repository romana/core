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
	"fmt"
	"log"
	"strings"

	"github.com/go-resty/resty"
	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
)

const (
	policiesPrefix = "/policies/"
)

// normalizePolicy
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
func (r *Romanad) distributePolicy(policy *api.Policy) error {
	hosts := r.client.IPAM.listHosts()
	for _, host := range hosts {
		url := fmt.Sprintf("http://%s:%d/policies", host.Name, host.AgentPort)
		log.Printf("Sending policy %s to agent at %s", policyDoc.Name, url)
		result := make(map[string]interface{})
		_, err := resty.R().SetResult(&result).SetBody(policyDoc).Post(url)
		log.Printf("Agent at %s returned %v", host.Name, result)
		if err != nil {
			errStr = append(errStr, fmt.Sprintf("Error applying policy %d to host %s: %v. ", policyDoc.ID, host.Ip, err))
		}
	}
	if len(errStr) > 0 {
		return common.NewError500(errStr)
	}
	return nil
}

// getPolicy is a handler for the /policy/{name} URL that
// returns the policy.
func (r *Romanad) getPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policyName := ctx.PathVariables["policy"]
	policy := &api.Policy{}
	err := r.client.Store.GetObject(policiesPrefix+policyName, policy)
	if err != nil {
		return nil, err
	}
	return policy, err
}

func (r *Romanad) deletePolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policyName := strings.TrimSpace(ctx.PathVariables["policy"])
	if policyName == "" {
		// This means we need to find information about what to delete in the body
		if input == nil {
			return nil, common.NewError400("Request must either be to /policies/{policy} or have a body.")
		}
		policy := input.(*api.Policy)
		err := policy.Validate()
		if err != nil {
			return nil, err
		}
		policyName = policy.Name
	}
	return nil, r.client.Store.Delete(policiesPrefix + policyName)
}

// listPolicies lists all policices.
func (r *Romanad) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
	r.client.Store.List()
}

// addPolicy stores the new policy and sends it to all agents.
func (r *Romanad) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {

}
