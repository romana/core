package enforcer

import (
	"testing"

	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/common/api"
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
		iptables := makeEmptyIptables()
		err := makePolicyRules(tc.policy, tc.schema, &iptables)
		t.Log(iptables.Render())
		t.Log(err)
	}
}
