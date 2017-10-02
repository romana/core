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
	"fmt"

	"github.com/romana/core/agent/iptsave"
)

// MakeBaseRules produces static iptables rules, that form backbone of romana policy flow.
// * ROMANA-FORWARD-IN captures all ingress traffic from world to pods.
// -A ROMANA-FORWARD-IN -m comment --comment Ingress -m state --state RELATED,ESTABLISHED -j ACCEPT
// -A ROMANA-FORWARD-IN -m comment --comment DefaultDrop -j DROP
//
// * ROMANA-FORWARD-OUT captures all egres traffic from pods to the world.
// -A ROMANA-FORWARD-OUT -m set --match-set localBlocks dst -j ROMANA-FORWARD-IN
// -A ROMANA-FORWARD-OUT -m comment --comment Egress -j ACCEPT
//
// * ROMANA-INPUT captures traffic from pods to the host.
// -A ROMANA-INPUT -j ACCEPT
//
// * ROMANA-OUTPUT captures traffic from host to the pods.
// -A ROMANA-OUTPUT -j ACCEPT
func MakeBaseRules() []*iptsave.IPchain {
	return []*iptsave.IPchain{
		&iptsave.IPchain{
			Name:   "ROMANA-OUTPUT",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ACCEPT",
					},
				},
			},
		},
		&iptsave.IPchain{
			Name:   "ROMANA-INPUT",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ACCEPT",
					},
				},
			},
		},
		&iptsave.IPchain{
			Name:   "ROMANA-FORWARD-OUT",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: fmt.Sprintf("-m set --match-set %s dst", LocalBlockSetName),
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ROMANA-FORWARD-IN",
					},
				},
				&iptsave.IPrule{
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-m comment --comment Egress",
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ACCEPT",
					},
				},
			},
		},
		&iptsave.IPchain{
			Name:   "ROMANA-FORWARD-IN",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-m comment --comment Ingress",
						},
						&iptsave.Match{
							Body: "-m state --state RELATED,ESTABLISHED",
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ACCEPT",
					},
				},
				&iptsave.IPrule{
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: MakeOperatorPolicyChainName(),
					},
				},
				&iptsave.IPrule{
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-m comment --comment DefaultDrop",
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "DROP",
					},
				},
			},
		},
		&iptsave.IPchain{
			Name:   MakeOperatorPolicyChainName(),
			Policy: "-",
			Rules: []*iptsave.IPrule{
				MakePolicyChainFooterRule(),
			},
		},
		&iptsave.IPchain{
			Name:   MakeOperatorPolicyIngressChainName(),
			Policy: "-",
			Rules: []*iptsave.IPrule{
				MakePolicyChainFooterRule(),
			},
		},
	}
}
