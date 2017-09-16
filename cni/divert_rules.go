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

package cni

import (
	"github.com/romana/core/agent/iptsave"
)

func MakeDivertRules(nodename string, op iptsave.RenderState) []*iptsave.IPchain {
	return []*iptsave.IPchain{
		&iptsave.IPchain{
			Name:   "ROMANA-INPUT",
			Policy: "-",
		},
		&iptsave.IPchain{
			Name:   "ROMANA-OUTPUT",
			Policy: "-",
		},
		&iptsave.IPchain{
			Name:   "ROMANA-FORWARD-IN",
			Policy: "-",
		},
		&iptsave.IPchain{
			Name:   "ROMANA-FORWARD-OUT",
			Policy: "-",
		},
		&iptsave.IPchain{
			Name:   "INPUT",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					RenderState: op,
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-i " + nodename,
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ROMANA-INPUT",
					},
				},
			},
		},
		&iptsave.IPchain{
			Name:   "FORWARD",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					RenderState: op,
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-i " + nodename,
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ROMANA-FORWARD-OUT",
					},
				},
			},
		},
		&iptsave.IPchain{
			Name:   "FORWARD",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					RenderState: op,
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-o " + nodename,
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ROMANA-FORWARD-IN",
					},
				},
			},
		},
		&iptsave.IPchain{
			Name:   "OUTPUT",
			Policy: "-",
			Rules: []*iptsave.IPrule{
				&iptsave.IPrule{
					RenderState: op,
					Match: []*iptsave.Match{
						&iptsave.Match{
							Body: "-o " + nodename,
						},
					},
					Action: iptsave.IPtablesAction{
						Type: iptsave.ActionDefault,
						Body: "ROMANA-OUTPUT",
					},
				},
			},
		},
	}
}
