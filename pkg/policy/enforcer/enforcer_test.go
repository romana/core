package enforcer

import (
	"github.com/romana/core/common"
	"github.com/romana/core/pkg/util/iptsave"
	"testing"
)

func TestMakeBase(t *testing.T) {
	// Make empty iptables object.
	iptables := iptsave.IPtables{
		Tables: []*iptsave.IPtable{
			&iptsave.IPtable{
				Name: "filter",
			},
		},
	}

	makeBase(&iptables)

	expected := `*filter
:ROMANA-INPUT -
:ROMANA-FORWARD-OUT -
:ROMANA-FORWARD-IN -
:ROMANA-OP -
-A ROMANA-INPUT -m state --state ESTABLISHED -j ACCEPT
-A ROMANA-INPUT -m comment --comment DefaultDrop -j DROP
-A ROMANA-FORWARD-OUT -m comment --comment Outgoing -j ACCEPT
-A ROMANA-FORWARD-OUT -j DROP
-A ROMANA-FORWARD-IN -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ROMANA-FORWARD-IN -j ROMANA-OP
-A ROMANA-FORWARD-IN -m comment --comment DefaultDrop -j DROP
-A ROMANA-OP -m comment --comment POLICY_CHAIN_FOOTER -j RETURN
COMMIT
`
	t.Log(iptables.Render())
	t.Log(expected)

	t.Log(iptables.Render() == expected)
}

type fakeTenantCache []common.Tenant

func (t fakeTenantCache) Run(stop <-chan struct{}) <-chan string {
	return make(chan string)
}
func (t fakeTenantCache) List() []common.Tenant {
	return []common.Tenant(t)
}

type fakePolicyCache []common.Policy

func (p fakePolicyCache) Run(stop <-chan struct{}) <-chan string {
	return make(chan string)
}
func (p fakePolicyCache) List() []common.Policy {
	return []common.Policy(p)
}

func TestMakeTenantRules(t *testing.T) {
	netConfig := MockNC{uint(8), uint(8), uint(4), uint(4), uint(8)}
	// Make empty iptables object.
	iptables := iptsave.IPtables{
		Tables: []*iptsave.IPtable{
			&iptsave.IPtable{
				Name: "filter",
			},
		},
	}

	tenants := []common.Tenant{
		common.Tenant{
			NetworkID: uint64(2),
			Segments: []common.Segment{
				common.Segment{
					NetworkID: uint64(20),
				},
				common.Segment{
					NetworkID: uint64(21),
				},
				common.Segment{
					NetworkID: uint64(22),
				},
			},
		},
		common.Tenant{
			NetworkID: uint64(1),
			Segments: []common.Segment{
				common.Segment{
					NetworkID: uint64(10),
				},
				common.Segment{
					NetworkID: uint64(11),
				},
				common.Segment{
					NetworkID: uint64(12),
				},
			},
		},
	}

	cache := fakeTenantCache(tenants)

	makeBase(&iptables)
	makeTenantRules(cache, netConfig, &iptables)

	t.Logf("\n%s", iptables.Render())
}

func TestMakePolicies(t *testing.T) {
	netConfig := MockNC{uint(8), uint(8), uint(4), uint(4), uint(8)}
	// Make empty iptables object.
	iptables := iptsave.IPtables{
		Tables: []*iptsave.IPtable{
			&iptsave.IPtable{
				Name: "filter",
			},
		},
	}

	tenants := []common.Tenant{
		common.Tenant{
			NetworkID: uint64(2),
			Segments: []common.Segment{
				common.Segment{
					NetworkID: uint64(20),
				},
				common.Segment{
					NetworkID: uint64(21),
				},
				common.Segment{
					NetworkID: uint64(22),
				},
			},
		},
		common.Tenant{
			NetworkID: uint64(1),
			Segments: []common.Segment{
				common.Segment{
					NetworkID: uint64(10),
				},
				common.Segment{
					NetworkID: uint64(11),
				},
				common.Segment{
					NetworkID: uint64(12),
				},
			},
		},
	}

	cache := fakeTenantCache(tenants)

	uintPtr := func(i int) *uint64 {
		u := uint64(i)
		return &u
	}

	policies := []common.Policy{
		common.Policy{
			Direction:  common.PolicyDirectionIngress,
			Name:       "pol-dhcp-vm",
			ExternalID: "FOO1",
			AppliedTo: []common.Endpoint{
				common.Endpoint{
					Dest: "local",
				},
			},
			Ingress: []common.RomanaIngress{
				common.RomanaIngress{
					Peers: []common.Endpoint{
						common.Endpoint{
							Peer: "host",
						},
					},
					Rules: []common.Rule{
						common.Rule{
							Ports:    []uint{uint(68)},
							Protocol: "UDP",
						},
					},
				},
			},
		},
		common.Policy{
			Direction:  common.PolicyDirectionIngress,
			Name:       "icmp-from-cidr",
			ExternalID: "ICMPCIDR",
			AppliedTo: []common.Endpoint{
				common.Endpoint{
					TenantNetworkID:  uintPtr(1),
					SegmentNetworkID: uintPtr(12),
				},
			},
			Ingress: []common.RomanaIngress{
				common.RomanaIngress{
					Peers: []common.Endpoint{
						common.Endpoint{
							Cidr: "200.1.2.0/24",
						},
					},
					Rules: []common.Rule{
						common.Rule{
							Protocol: "ICMP",
						},
					},
				},
			},
		},
		common.Policy{
			Direction:  common.PolicyDirectionIngress,
			Name:       "tcp-from-tenant",
			ExternalID: "TCPTENANT",
			AppliedTo: []common.Endpoint{
				common.Endpoint{
					TenantNetworkID:  uintPtr(2),
					SegmentNetworkID: uintPtr(21),
				},
			},
			Ingress: []common.RomanaIngress{
				common.RomanaIngress{
					Peers: []common.Endpoint{
						common.Endpoint{
							TenantNetworkID:  uintPtr(1),
							SegmentNetworkID: uintPtr(12),
						},
					},
					Rules: []common.Rule{
						common.Rule{
							Protocol: "TCP",
							Ports:    []uint{80, 443},
						},
					},
				},
			},
		},
		common.Policy{
			Direction:  common.PolicyDirectionIngress,
			Name:       "any-from-host",
			ExternalID: "ANY4HOST",
			AppliedTo: []common.Endpoint{
				common.Endpoint{
					Dest: "local",
				},
			},
			Ingress: []common.RomanaIngress{
				common.RomanaIngress{
					Peers: []common.Endpoint{
						common.Endpoint{
							Peer: "host",
						},
					},
					Rules: []common.Rule{
						common.Rule{
							Protocol: "ANY",
						},
					},
				},
			},
		},
	}

	policyCache := fakePolicyCache(policies)
	makeBase(&iptables)
	makeTenantRules(cache, netConfig, &iptables)
	makePolicies(policyCache, netConfig, &iptables)

	t.Logf("Policies rendered \n%s", iptables.Render())
}
