package enforcer

import (
	"net"
	"testing"

	"github.com/romana/core/agent/internal/cache/policycache"
	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/common/api"
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
	_ = withTenantSegment

	makeRules := func(rules ...api.Rule) (result []api.Rule) {
		for _, r := range rules {
			result = append(result, r)
		}
		return result
	}
	withProtoPorts := func(proto string, ports ...uint) api.Rule {
		return api.Rule{Protocol: proto, Ports: ports}
	}

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

	testCases := []struct {
		name   string
		schema string
		policy api.Policy
	}{
		{
			name:   "ingress basic",
			schema: SchemePolicyOnTop,
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
			schema: SchemeTargetOnTop,
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

	for _, tc := range testCases {
		sets := ipset.Ipset{}
		iptables := makeEmptyIptables()
		err := makePolicyRules(tc.policy, tc.schema, blocks, &iptables)
		t.Log(iptables.Render())
		t.Log(sets.Render(ipset.RenderCreate))
		t.Log(err)
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
	_ = withTenantSegment

	makeRules := func(rules ...api.Rule) (result []api.Rule) {
		for _, r := range rules {
			result = append(result, r)
		}
		return result
	}
	withProtoPorts := func(proto string, ports ...uint) api.Rule {
		return api.Rule{Protocol: proto, Ports: ports}
	}

	testCases := []struct {
		name   string
		policy api.Policy
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
						Rules: makeRules(withProtoPorts("TCP", 80, 99, 8080)),
					},
				},
			},
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
						Rules: makeRules(
							withProtoPorts("TCP", 80, 99, 8080),
							withProtoPorts("UDP", 53, 1194),
						),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		set1, set2, err := makePolicySets(tc.policy)
		sets := ipset.Ipset{Sets: []*ipset.Set{set1, set2}}
		t.Log(sets.Render(ipset.RenderSave))
		t.Log(err)
	}
}

func TestMakeBlockSets(t *testing.T) {

	makeCIDR := func(s string) api.IPNet {
		_, ipnet, _ := net.ParseCIDR(s)
		return api.IPNet{*ipnet}
	}

	testCases := []struct {
		name       string
		hostname   string
		blockCache []api.IPAMBlockResponse
	}{
		{
			name:     "basic 1",
			hostname: "host1",
			blockCache: []api.IPAMBlockResponse{
				api.IPAMBlockResponse{
					Tenant:  "T800",
					Segment: "john",
					CIDR:    makeCIDR("10.0.0.0/28"),
				},
				api.IPAMBlockResponse{
					Tenant:  "T100k",
					Segment: "skynet",
					CIDR:    makeCIDR("10.1.0.0/28"),
				},
			},
		},
	}

	for _, tc := range testCases {
		sets, err := makeBlockSets(tc.blockCache, policycache.New(), tc.hostname)
		t.Log(sets.Render(ipset.RenderSave))
		t.Log(err)
	}
}
