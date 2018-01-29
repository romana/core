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
	"strings"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/api/errors"
	"github.com/romana/core/common/client"
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
	if req.Name == "" {
		return nil, common.NewError400("Name required")
	}
	if req.Host == "" {
		return nil, common.NewError400("Host required")
	}
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

// getTopology returns the latest Romana Topology in kvstore (etcd).
func (r *Romanad) getTopology(input interface{}, ctx common.RestContext) (interface{}, error) {
	return r.client.GetTopology()
}

// updateTopology serves to update topology information in the Romana service
func (r *Romanad) updateTopology(input interface{}, ctx common.RestContext) (interface{}, error) {
	topoReq := input.(*api.TopologyUpdateRequest)
	return nil, r.client.IPAM.UpdateTopology(*topoReq, true)
}

// getPolicy is a handler for the /policy/{name} URL that
// returns the policy.
func (r *Romanad) getPolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policyName := ctx.PathVariables["policy"]
	policy, err := r.client.GetPolicy(client.PoliciesPrefix + policyName)
	if err != nil {
		return nil, err
	}
	return policy, err
}

func (r *Romanad) deletePolicy(input interface{}, ctx common.RestContext) (interface{}, error) {
	policyID := strings.TrimSpace(ctx.PathVariables["policyID"])
	if policyID == "" {
		// This means we need to find information about what to delete in the body
		if input == nil {
			return nil, common.NewError400("Request must either be to /policies/{policyID} or have a body.")
		}
		policy, ok := input.(*api.Policy)
		// just checking policy ID is good here, no need
		// to validate whole policy before deleting it.
		if !ok || policy.ID == "" {
			return nil, common.NewUnprocessableEntityError("Policy ID not found in input")
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
