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

package enforcer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/romana/core/agent/internal/cache/policycache"
	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/common/api"
	"github.com/romana/core/pkg/policytools"
	"github.com/romana/ipset"
)

func TestMakePolicyRules(t *testing.T) {
	makeEmptyIptables := func() iptsave.IPtables {
		return iptsave.IPtables{
			Tables: []*iptsave.IPtable{
				&iptsave.IPtable{
					Name: "filter",
				},
			},
		}
	}

	makeEndpoints := func(endpoints ...api.Endpoint) (result []api.Endpoint) {
		for _, e := range endpoints {
			result = append(result, e)
		}
		return
	}

	withCidr := func(s ...string) api.Endpoint {
		return api.Endpoint{Cidr: s[0]}
	}
	withTenant := func(t ...string) api.Endpoint {
		return api.Endpoint{TenantID: t[0]}
	}
	withTenantSegment := func(s ...string) api.Endpoint {
		return api.Endpoint{TenantID: s[0], SegmentID: s[1]}
	}

	makeRules := func(rules ...api.Rule) (result []api.Rule) {
		for _, r := range rules {
			result = append(result, r)
		}
		return result
	}
	withProtoPorts := func(proto string, ports ...uint) api.Rule {
		return api.Rule{Protocol: proto, Ports: ports}
	}

	/* example blocks for using in tests
	blocks := []api.IPAMBlockResponse{
		api.IPAMBlockResponse{
			Tenant:  "T800",
			Segment: "John",
		},
		api.IPAMBlockResponse{
			Tenant:  "T1000",
			Segment: "",
		},
		api.IPAMBlockResponse{
			Tenant:  "T3000",
			Segment: "",
		},
		api.IPAMBlockResponse{
			Tenant:  "T100K",
			Segment: "skynet",
		},
	}
	*/

	testCases := []struct {
		name   string
		schema string
		policy api.Policy
	}{
		{
			name:   "ingress basic",
			schema: policytools.SchemePolicyOnTop,
			policy: api.Policy{
				ID:        "<TESTPOLICYID>",
				Direction: api.PolicyDirectionIngress,
				AppliedTo: makeEndpoints(withTenant("T1000")),
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{
						Peers: makeEndpoints(withCidr("10.0.0.0/99")),
						Rules: makeRules(withProtoPorts("TCP", 80, 99, 8080)),
					},
				},
			},
		},
		{
			name:   "egress basic",
			schema: policytools.SchemeTargetOnTop,
			policy: api.Policy{
				ID:        "<TESTPOLICYID>",
				Direction: api.PolicyDirectionEgress,
				AppliedTo: makeEndpoints(withTenant("T1000"), withTenantSegment("T800", "John")),
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{
						Peers: makeEndpoints(
							withCidr("10.0.0.0/99"),
							withTenant("T3000"),
							withTenantSegment("T100K", "skynet")),
						Rules: makeRules(
							withProtoPorts("TCP", 80, 99, 8080),
							withProtoPorts("UDP", 53, 1194),
						),
					},
				},
			},
		},
	}

	toList := func(p ...api.Policy) []api.Policy {
		return p
	}

	noop := func(target api.Endpoint) bool { return true }

	for _, tc := range testCases {
		sets := ipset.Ipset{}
		iptables := makeEmptyIptables()
		makePolicies(toList(tc.policy), noop, &iptables)
		t.Log(iptables.Render())
		t.Log(sets.Render(ipset.RenderCreate))
	}
}

func TestMakePolicySets(t *testing.T) {
	makeEndpoints := func(endpoints ...api.Endpoint) (result []api.Endpoint) {
		for _, e := range endpoints {
			result = append(result, e)
		}
		return
	}

	withCidr := func(s ...string) api.Endpoint {
		return api.Endpoint{Cidr: s[0]}
	}
	withTenant := func(t ...string) api.Endpoint {
		return api.Endpoint{TenantID: t[0]}
	}
	withTenantSegment := func(s ...string) api.Endpoint {
		return api.Endpoint{TenantID: s[0], SegmentID: s[1]}
	}

	// expectFunc is a signature for a function used in test cases to
	// assert test success.
	type expectFunc func(*ipset.Set, error) error

	// return expectFunc that looks for provided cidrs in Set.
	matchIpsetMember := func(cidrs ...string) expectFunc {
		return func(set *ipset.Set, err error) error {
			for _, cidr := range cidrs {
				for _, member := range set.Members {
					if member.Elem == cidr {
						// found
						continue
					}

					return fmt.Errorf("cidr %s not found in set %v",
						cidr, set)
				}
			}

			return nil
		}

	}

	testCases := []struct {
		name   string
		policy api.Policy
		expect expectFunc
	}{
		{
			name: "ingress sets basic",
			policy: api.Policy{
				ID:        "<TESTPOLICYID>",
				Direction: api.PolicyDirectionIngress,
				AppliedTo: makeEndpoints(withTenant("T1000")),
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{
						Peers: makeEndpoints(withCidr("10.0.0.0/99")),
					},
				},
			},
			expect: matchIpsetMember("10.0.0.0/99"),
		},
		{
			name: "egress sets basic",
			policy: api.Policy{
				ID:        "<TESTPOLICYID>",
				Direction: api.PolicyDirectionEgress,
				AppliedTo: makeEndpoints(withTenant("T1000"), withTenantSegment("T800", "John")),
				Ingress: []api.RomanaIngress{
					api.RomanaIngress{
						Peers: makeEndpoints(
							withCidr("10.0.0.0/99"),
							withTenant("T3000"),
							withTenantSegment("T100K", "skynet")),
					},
				},
			},
			expect: matchIpsetMember("10.0.0.0/99"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			set1, err := makePolicySets(tc.policy)
			sets := ipset.Ipset{Sets: []*ipset.Set{set1}}
			t.Log(sets.Render(ipset.RenderSave))

			err = tc.expect(set1, err)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestMakeBlockSets(t *testing.T) {

	makeCIDR := func(s string) api.IPNet {
		_, ipnet, _ := net.ParseCIDR(s)
		return api.IPNet{IPNet: *ipnet}
	}

	// expectFunc is a signature for a function used in test cases to
	// assert test success.
	type expectFunc func(*ipset.Ipset, error) error

	// return expectFunc that looks for provided elems in Set.
	matchElemInSet := func(setname string, elems ...string) expectFunc {
		return func(sets *ipset.Ipset, err error) error {
			set := sets.SetByName(setname)

			if set == nil {
				return fmt.Errorf("no such set %s", setname)
			}

			for _, elem := range elems {
				found := false
				for _, member := range set.Members {
					if member.Elem == elem {
						found = true
						continue
					}

				}
				if !found {
					return fmt.Errorf("elem %s not found in set %v",
						elem, set)
				}
			}

			return nil
		}
	}

	// returns expectFunc that checks that provided elems not included on Set.
	matchElemNotInSet := func(setname string, elems ...string) expectFunc {
		return func(sets *ipset.Ipset, err error) error {
			err = matchElemInSet(setname, elems...)(sets, nil)
			if err != nil {
				return nil
			}

			return fmt.Errorf("at least one of %v found in %s", elems, setname)
		}
	}

	testCases := []struct {
		name       string
		hostname   string
		blockCache []api.IPAMBlockResponse
		expect     []expectFunc
	}{
		{
			name:     "basic 1",
			hostname: "host1",
			blockCache: []api.IPAMBlockResponse{
				api.IPAMBlockResponse{
					Tenant:  "T800",
					Segment: "john",
					CIDR:    makeCIDR("10.0.0.0/28"),
					Host:    "host1",
				},
				api.IPAMBlockResponse{
					Tenant:  "T100k",
					Segment: "skynet",
					CIDR:    makeCIDR("10.1.0.0/28"),
					Host:    "host1",
				},
				api.IPAMBlockResponse{
					Tenant:  "T34",
					Segment: "pirozhok",
					CIDR:    makeCIDR("192.168.1.0/28"),
					Host:    "host2",
				},
			},
			expect: []expectFunc{
				// test proper cidrs in local blocks
				matchElemInSet(LocalBlockSetName, "10.1.0.0/28", "10.0.0.0/28"),

				// test local blocks don't get wrong cidrs
				matchElemNotInSet(LocalBlockSetName, "192.168.1.0/28"),

				// test segment set has appropriate cidr
				matchElemInSet(policytools.MakeTenantSetName("T800", "john"), "10.0.0.0/28"),

				// test tenant set has segment set
				matchElemInSet(policytools.MakeTenantSetName("T800", ""),
					policytools.MakeTenantSetName("T800", "john")),
			},
		},
	}

	for _, tc := range testCases {
		sets, err := makeBlockSets(tc.blockCache, policycache.New(), tc.hostname)
		t.Log(sets.Render(ipset.RenderSave))

		for _, expect := range tc.expect {
			err := expect(sets, err)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

var tdir = "testdata"

func TestMakePolicies(t *testing.T) {
	files, err := ioutil.ReadDir(tdir)
	if err != nil {
		t.Skip("Folder with test data not found")
	}

	loadRomanaPolicy := func(file string) (*api.Policy, error) {
		data, err := ioutil.ReadFile(filepath.Join(tdir, file))
		if err != nil {
			return nil, err
		}

		var policy api.Policy

		err = json.Unmarshal(data, &policy)

		if err != nil {
			return nil, err
		}

		return &policy, nil
	}

	toList := func(p ...api.Policy) []api.Policy {
		return p
	}

	noop := func(target api.Endpoint) bool { return true }
	_ = loadRomanaPolicy

	test := func(file string, t *testing.T) func(*testing.T) {
		return func(t *testing.T) {
			policy, err := loadRomanaPolicy(file)
			if err != nil {
				t.Fatal(err)
			}

			iptables := iptsave.IPtables{
				Tables: []*iptsave.IPtable{
					&iptsave.IPtable{
						Name: "filter",
					},
				},
			}

			makePolicies(toList(*policy), noop, &iptables)

			referenceName := strings.Replace(file, ".json", ".iptables", -1)

			// generate golden files
			if os.Getenv("MAKE_GOLD") != "" {
				err = ioutil.WriteFile(filepath.Join(tdir, referenceName), []byte(iptables.Render()), 0644)
				if err != nil {
					t.Fatal(err)
				}

				return
			}

			referenceFile, err := ioutil.ReadFile(filepath.Join(tdir, referenceName))
			if err != nil {
				t.Fatal(err)
			}

			if string(referenceFile) != iptables.Render() {
				t.Fatal(file)
			}
		}
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			t.Run(file.Name(), test(file.Name(), t))
		}
	}
}

func TestTargetValid(t *testing.T) {
	testCases := []struct {
		name   string
		target api.Endpoint
		blocks []api.IPAMBlockResponse
		expect bool
	}{
		{
			name:   "basic invalid target",
			target: api.Endpoint{TenantID: "T1000"},
			expect: false,
		},
		{
			name:   "target doesn't match tenant",
			target: api.Endpoint{Peer: "any"},
			expect: true,
		},
		{
			name:   "target invalid due to no corresponding tenant blocks",
			target: api.Endpoint{TenantID: "T1000"},
			blocks: []api.IPAMBlockResponse{
				api.IPAMBlockResponse{
					Tenant:  "T800",
					Segment: "John",
				},
			},
			expect: false,
		},
		{
			name:   "target invalid, no corresponding segment",
			target: api.Endpoint{TenantID: "T100K", SegmentID: "skynet"},
			blocks: []api.IPAMBlockResponse{
				api.IPAMBlockResponse{
					Tenant:  "T800",
					Segment: "John",
				},
			},
			expect: false,
		},
		{
			name:   "target is invalid, matches tenant",
			target: api.Endpoint{TenantID: "T800"},
			blocks: []api.IPAMBlockResponse{
				api.IPAMBlockResponse{
					Tenant:  "T800",
					Segment: "John",
				},
			},
			expect: true,
		},
		{
			name:   "target is valid, matches tenant and segment",
			target: api.Endpoint{TenantID: "T800", SegmentID: "John"},
			blocks: []api.IPAMBlockResponse{
				api.IPAMBlockResponse{
					Tenant:  "T800",
					Segment: "John",
				},
			},
			expect: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := targetValid(tc.target, tc.blocks)
			if result != tc.expect {
				t.Fatalf("unexpected result %t", result)
			}
		})
	}
}
