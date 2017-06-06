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

// Static iptables rules, that form backbone of romana policy flow. Do not
// depend on any tenants, pods or policies.

package enforcer

import (
	"github.com/romana/core/agent/iptsave"
)

func MakeBaseRules() []*iptsave.IPchain {
	return []*iptsave.IPchain{
		&iptsave.IPchain{
			Name:   "ROMANA-INPUT",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-m state --state ESTABLISHED",
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
						Body: MakeOperatorPolicyIngressChainName(),
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
			Name:   "ROMANA-FORWARD-OUT",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-m comment --comment Outgoing",
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "RETURN",
					},
				},
				&iptsave.IPrule{
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "DROP",
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
