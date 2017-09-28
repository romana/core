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
	"strconv"
	"strings"

	"github.com/go-resty/resty"
	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/api/errors"
	"github.com/romana/core/common/client"
	"github.com/romana/core/pkg/policytools"
)

// deallocateIP deallocates IP specified by query parameter
// "addressName".
func (r *Romanad) deallocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	addressName := ctx.QueryVariables.Get("addressName")
	err := r.client.IPAM.DeallocateIP(addressName)
	return nil, errors.RomanaErrorToHTTPError(err)
}

func (r *Romanad) allocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	req := input.(*api.IPAMAddressRequest)
	retval, err := r.client.IPAM.AllocateIP(req.Name, req.Host, req.Tenant, req.Segment)
	return retval, errors.RomanaErrorToHTTPError(err)
}

// listHosts returns all hosts.
func (r *Romanad) listHosts(input interface{}, ctx common.RestContext) (interface{}, error) {
	return r.client.IPAM.ListHosts(), nil
}

func (r *Romanad) listNetworkBlocks(input interface{}, ctx common.RestContext) (interface{}, error) {
	netName := ctx.PathVariables["network"]
	return r.client.IPAM.ListNetworkBlocks(netName), nil
}

func (r *Romanad) listAllBlocks(input interface{}, ctx common.RestContext) (interface{}, error) {
	return r.client.IPAM.ListAllBlocks(), nil
}

func (r *Romanad) listAddresses(input interface{}, ctx common.RestContext) (interface{}, error) {
	netName := ctx.PathVariables["network"]
	blockID, err := strconv.Atoi(ctx.PathVariables["block"])
	addresses := make([]string, 0)
	if err != nil {
		return nil, err
	}
	if network, ok := r.client.IPAM.Networks[netName]; ok {
		blocks := network.Group.ListBlocks()

		for i, block := range blocks {
			if i == blockID {
				blockAddresses := block.ListAllocatedAddresses()
				addresses = append(addresses, blockAddresses...)
			}
		}
		return addresses, nil
	}
	return nil, common.NewError404("network", netName)
}

func (r *Romanad) listNetworks(input interface{}, ctx common.RestContext) (interface{}, error) {
	resp := make([]api.IPAMNetworkResponse, 0)
	for _, network := range r.client.IPAM.Networks {
		n := api.IPAMNetworkResponse{
			CIDR:     api.IPNet{IPNet: *network.CIDR.IPNet},
			Name:     network.Name,
			Revision: network.Revison,
		}
		resp = append(resp, n)
	}
	return resp, nil
}

// updateTopology serves to update topology information in the Romana service
func (r *Romanad) updateTopology(input interface{}, ctx common.RestContext) (interface{}, error) {
	topoReq := input.(*api.TopologyUpdateRequest)
	return nil, r.client.IPAM.UpdateTopology(*topoReq)
}

// normalizePolicy
func (r *Romanad) normalizePolicy(policyDoc *api.Policy) error {
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
	hosts := r.client.IPAM.ListHosts()
	var errStr string
	for _, host := range hosts.Hosts {
		url := fmt.Sprintf("http://%s:%d/policies", host.IP, host.AgentPort)
		log.Printf("Sending policy %s to agent at %s", policy.ID, url)
		result := make(map[string]interface{})
		_, err := resty.R().SetResult(&result).SetBody(policy).Post(url)
		log.Printf("Agent at %s returned %v", host.IP, result)
		if err != nil {
			if len(errStr) > 0 {
				errStr += "; "
			}
			errStr += fmt.Sprintf("Error applying policy %s to host %s: %v. ", policy.ID, host.IP, err)
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
	policy, err := r.client.GetPolicy(client.PoliciesPrefix+policyName)
	if err != nil {
		return nil, err
	}
	return policy, err
}

func (r *Romanad) deletePolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policyID := strings.TrimSpace(ctx.PathVariables["policy"])
	if policyID == "" {
		// This means we need to find information about what to delete in the body
		if input == nil {
			return nil, common.NewError400("Request must either be to /policies/{policy} or have a body.")
		}
		policy := input.(*api.Policy)
		err := policytools.ValidatePolicy(*policy)
		if err != nil {
			return nil, common.NewUnprocessableEntityError(err.Error())
		}

		policyID = policy.ID
	}
	found, err := r.client.DeletePolicy(policyID)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, nil
	} else {
		return nil, common.NewError404("policy", policyID)
	}
}

// listPolicies lists all policices.
func (r *Romanad) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
	return r.client.ListPolicies()
}

// addPolicy stores the new policy and sends it to all agents.
func (r *Romanad) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policy := input.(*api.Policy)
	return nil, r.client.AddPolicy(*policy)
}

// addPolicy stores the new policy and sends it to all agents.
func (r *Romanad) addHost(input interface{}, ctx common.RestContext) (interface{}, error) {
	host := input.(*api.Host)
	err := r.client.IPAM.AddHost(*host)
	return nil, errors.RomanaErrorToHTTPError(err)
}
