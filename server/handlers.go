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
)

const (
	policiesPrefix = "/policies"
)

// deallocateIP deallocates IP specified by query parameter
// "addressName".
func (r *Romanad) deallocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	addressName := ctx.QueryVariables.Get("addressName")
	return nil, r.client.IPAM.DeallocateIP(addressName)
}

func (r *Romanad) allocateIP(input interface{}, ctx common.RestContext) (interface{}, error) {
	req := input.(api.IPAMAddressRequest)
	return r.client.IPAM.AllocateIP(req.Name, req.Host, req.Tenant, req.Segment)
}

// listHosts returns all hosts.
func (r *Romanad) listHosts(input interface{}, ctx common.RestContext) (interface{}, error) {
	return r.client.IPAM.ListHosts(), nil
}

// listBlocks returns api.IPAMBlocksResponse containing blocks in the given network.
// The network is specified with the "network" query parameter.
func (r *Romanad) listBlocks(input interface{}, ctx common.RestContext) (interface{}, error) {
	netName := ctx.PathVariables["network"]
	if network, ok := r.client.IPAM.Networks[netName]; ok {
		resp := api.IPAMBlocksResponse{
			Revision: network.Revison,
			Blocks:   network.HostsGroups.GetBlocksResponse(),
		}
		return resp, nil
	} else {
		return nil, common.NewError404("network", netName)
	}
}

func (r *Romanad) listAddresses(input interface{}, ctx common.RestContext) (interface{}, error) {
	netName := ctx.PathVariables["network"]
	blockID, err := strconv.Atoi(ctx.PathVariables["block"])
	addresses := make([]string, 0)
	if err != nil {
		return nil, err
	}
	if network, ok := r.client.IPAM.Networks[netName]; ok {
		blocks := network.HostsGroups.ListBlocks()

		for i, block := range blocks {
			if i == blockID {
				blockAddresses := block.ListAddresses()
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
	topoReq := input.(api.TopologyUpdateRequest)
	return nil, r.client.IPAM.UpdateTopology(topoReq)
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
	for _, host := range hosts {
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
		policyName = policy.ID
	}
	return nil, r.client.Store.Delete(policiesPrefix + policyName)
}

// listPolicies lists all policices.
func (r *Romanad) listPolicies(input interface{}, ctx common.RestContext) (interface{}, error) {
	return r.client.Store.ListObjects(policiesPrefix, &api.Policy{})
}

// addPolicy stores the new policy and sends it to all agents.
func (r *Romanad) addPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policy := input.(*api.Policy)
	return nil, r.client.Store.PutObject(policiesPrefix+policy.ID, policy)
}
