// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

/*
   This file contains types that wrap common.Policy, api.Endpoint
   and a few other types related to the common.Policy.
   Types in this file required to support Canonical method of the Policy
   which is used in hashing.
   Sorting is done using standard library `sort.Sort` interface that
   relies on a method `Less()` of the receiver type for the sort criteria.
*/

package policyhasher

import (
	"fmt"
	"sort"

	"github.com/romana/core/common/api"
)

// PolicyToCanonical sorts romana policy Ingress and AppliedTo fields.
func PolicyToCanonical(unsorted api.Policy) api.Policy {
	sorted := api.Policy{
		Direction:   unsorted.Direction,
		Description: unsorted.Description,
		ID:          unsorted.ID,
	}

	sorted.AppliedTo = NewEndpointList(unsorted.AppliedTo).Sort().List()

	for _, ingress := range unsorted.Ingress {
		sorted.Ingress = append(sorted.Ingress, IngressToCanonical(ingress))
	}

	return sorted
}

// EndpointList implements sort.Interface to allow sorting of []api.Endpoint.
type EndpointList struct {
	items []EndpointSortGroup
}

func (p EndpointList) Len() int      { return len(p.items) }
func (p EndpointList) Swap(i, j int) { p.items[i], p.items[j] = p.items[j], p.items[i] }

// Less compares endpoints using their string representations, implements sort.Interface.
func (p EndpointList) Less(i, j int) bool { return p.items[i].key < p.items[j].key }

// NewEndpointList converts list of api.Endpoint into EndpointList for later sorting.
func NewEndpointList(endpoints []api.Endpoint) EndpointList {
	endpointList := EndpointList{}

	for _, e := range endpoints {
		key := EndpointToString(e)
		endpointList.items = append(endpointList.items, EndpointSortGroup{endpoint: e, key: key})
	}

	return endpointList
}

// Sort is a convinience method to sort EndpointList, returns EndpointList to
// allow method chaining.
func (p EndpointList) Sort() EndpointList {
	sort.Sort(p)
	return p
}

// List converts EndpointList into []api.Endpoint.
func (p EndpointList) List() []api.Endpoint {
	list := []api.Endpoint{}
	for _, item := range p.items {
		list = append(list, item.endpoint)
	}

	return list
}

// EndpointSortGroup is an auxillary structure for the EndpointList,
// it contains original endpoint and precalculated string representation
// which will be used as a sorting criteria by EndpointList.Sort().
type EndpointSortGroup struct {
	endpoint api.Endpoint
	key      string
}

// EndpointToString returns string representation of the api.Endpoint.
func EndpointToString(e api.Endpoint) string {
	return fmt.Sprintf("%s%s%s%s%s", e.Peer, e.Cidr, e.Dest, e.TenantID, e.SegmentID)
}

// IngressToCanonical returns canonical version of common.RomanaIngress.
func IngressToCanonical(unsorted api.RomanaIngress) api.RomanaIngress {
	sorted := api.RomanaIngress{}

	sorted.Peers = NewEndpointList(unsorted.Peers).Sort().List()

	for _, rule := range unsorted.Rules {
		sorted.Rules = append(sorted.Rules, RuleToCanonical(rule))
	}

	return sorted
}

// UintSlice satisfies sort.Interface to allow sorting of a []uint.
type UintSlice []uint

func (p UintSlice) Len() int           { return len(p) }
func (p UintSlice) Less(i, j int) bool { return p[i] < p[j] }
func (p UintSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// RuleToCanonical sorts api.Rule Ports and PortRanges fields.
func RuleToCanonical(unsorted api.Rule) api.Rule {
	// copy args
	sorted := unsorted

	// Convert list of ports into UintSlice for sorting
	// and then back to []uint.
	ports := UintSlice(sorted.Ports)
	sort.Sort(ports)
	sorted.Ports = []uint(ports)

	// Convert list of []PortRange into PortRangeSlice for sorting
	// and then back to []PortRange
	ranges := PortRangeSlice(sorted.PortRanges)
	sort.Sort(ranges)
	sorted.PortRanges = []api.PortRange(ranges)

	return sorted
}

// RuleToString generates string representation of the api.Rule.
func RuleToString(rule api.Rule) string {
	newRule := RuleToCanonical(rule)
	var result string
	result += rule.Protocol

	for _, p := range newRule.Ports {
		result += fmt.Sprintf("%d", p)
	}

	for _, p := range newRule.PortRanges {
		result += fmt.Sprintf("%d%d", p[0], p[1])
	}

	result += fmt.Sprintf("%d%d%t", newRule.IcmpType, newRule.IcmpCode, newRule.IsStateful)

	return result
}

// RuleSlice implements sort.Interface to allow sorting of the []api.Rule.
type RuleSlice []api.Rule

func (p RuleSlice) Len() int           { return len(p) }
func (p RuleSlice) Less(i, j int) bool { return RuleToString(p[i]) < RuleToString(p[j]) }
func (p RuleSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// RulesToCanonical returns canonical version of a []api.Rule.
func RulesToCanonical(unsorted []api.Rule) []api.Rule {
	var sorted RuleSlice

	for _, r := range unsorted {
		sorted = append(sorted, RuleToCanonical(r))
	}

	sort.Sort(sorted)
	ret := []api.Rule(sorted)

	return ret
}

// PortRangeSlice implements sort.Interface to allow sorting of the []common.PortRange.
type PortRangeSlice []api.PortRange

func (p PortRangeSlice) Len() int { return len(p) }

// Less compares port ranges based on difference between low and high port number.
func (p PortRangeSlice) Less(i, j int) bool { return p[i][0]-p[i][1] < p[j][0]-p[j][1] }
func (p PortRangeSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
