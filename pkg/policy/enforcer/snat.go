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

// Policy enforcer package translates romana policies into iptables rules.
package enforcer

import (
	"fmt"
	"github.com/romana/core/common"
	utilexec "github.com/romana/core/pkg/util/exec"
	"github.com/romana/core/pkg/util/iptsave"
	log "github.com/romana/rlog"
	"os"
	"strings"
)

type snatConfig struct {
	natIf       string
	natIp       string
	excludeNets string
}

func checkFeatureSnatEnabled() bool {
	if os.Getenv("ROMANA_FEATURE_SNAT") == "enable" {
		return true
	}

	return false
}

func getFeatureSnatConfig() (*snatConfig, error) {
	config := snatConfig{
		natIf:       os.Getenv("ROMANA_FEATURE_SNAT_NATIF"),
		natIp:       os.Getenv("ROMANA_FEATURE_SNAT_NATIP"),
		excludeNets: os.Getenv("ROMANA_FEATURE_SNAT_EXCLUDE"),
	}

	if config.natIf == "" {
		return &config, common.NewError("ROMANA_FEATURE_SNAT_NATIF must be set to interface name.")
	}

	return &config, nil
}

func featureSnat(iptables *iptsave.IPtables, exec utilexec.Executable) {
	if !checkFeatureSnatEnabled() {
		return
	}

	config, err := getFeatureSnatConfig()
	if err != nil {
		log.Errorf("Feature SNAT enabled but config variable isn't set correctly, ignoring - %s", err)
		return
	}

	currentIptables, err := LoadIPtables(exec)
	if err != nil {
		log.Errorf("Feature SNAT enabled but failed to load nat rules - %s", err)
		return
	}

	// Check if jump rule for this feature already installed.
	// *nat
	// -A POSTROUTING -j ROMANA_FEATURE_SNAT
	var featureNatJump bool
	currentNat := currentIptables.TableByName("nat")
	if currentNat != nil {
		currentPostrouting := currentNat.ChainByName("POSTROUTING")
		if currentPostrouting != nil {
			featureNatJump = featureSnatJumpRuleInChain(currentPostrouting)
		}
	}

	log.Tracef(4, "Iptables has %d tables before nat", len(iptables.Tables))
	// Add *nat table if not there already.
	natTable := iptables.TableByName("nat")
	if natTable == nil {
		natTable = &iptsave.IPtable{
			Name: "nat",
		}
		log.Tracef(4, "adding nat table")
		iptables.Tables = append(iptables.Tables, natTable)
		log.Tracef(4, "Iptables has %d tables right after nat", len(iptables.Tables))
	}
	log.Tracef(4, "Iptables has %d tables after nat", len(iptables.Tables))
	log.Tracef(4, "Nattable %v, %T", natTable, natTable)

	// Add postrouting chain if not there alaready.
	postroutingChain := natTable.ChainByName("POSTROUTING")
	if postroutingChain == nil {
		postroutingChain = &iptsave.IPchain{Name: "POSTROUTING", Policy: "-"}
		natTable.Chains = append(natTable.Chains, postroutingChain)
	}

	if !featureNatJump {
		postroutingChain.Rules = append(postroutingChain.Rules, MakeSimpleJumpRule("ROMANA_FEATURE_SNAT"))
	}

	featureChain := &iptsave.IPchain{
		Name:   "ROMANA_FEATURE_SNAT",
		Policy: "-",
	}

	natTable.Chains = append(natTable.Chains, featureChain)

	var featureSnatTarget string
	if config.natIp != "" {
		featureSnatTarget = fmt.Sprintf("SNAT --to %s", config.natIp)
	} else {
		featureSnatTarget = "SNAT"
	}

	for _, cidr := range strings.Split(config.excludeNets, ",") {
		featureChain.Rules = append(featureChain.Rules,
			&iptsave.IPrule{
				Match: []*iptsave.Match{
					&iptsave.Match{
						Body: fmt.Sprintf("-o %s", config.natIf),
					},
					&iptsave.Match{
						Body: fmt.Sprintf("-d %s", cidr),
					},
				},
				Action: iptsave.IPtablesAction{
					Type: iptsave.ActionDefault,
					Body: "RETURN",
				},
			})
	}

	featureChain.Rules = append(featureChain.Rules,
		&iptsave.IPrule{
			Action: iptsave.IPtablesAction{
				Type: iptsave.ActionOther,
				Body: featureSnatTarget,
			},
		},
	)

	log.Tracef(4, "Iptables after enabling SNAT feature\n%s", iptables.Render())
}

func featureSnatJumpRuleInChain(chain *iptsave.IPchain) bool {
	for _, rule := range chain.Rules {
		if rule.Action.Body == "ROMANA_FEATURE_SNAT" {
			return true
		}
	}

	return false
}
