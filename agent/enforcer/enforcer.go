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
	"strings"
	"time"

	utilexec "github.com/romana/core/agent/exec"
	"github.com/romana/core/agent/firewall"
	"github.com/romana/core/agent/iptsave"
	policyCache "github.com/romana/core/agent/policy/cache"
	tenantCache "github.com/romana/core/agent/tenant/cache"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"

	log "github.com/romana/rlog"
)

// Interface defines policy enforcer behavior.
type Interface interface {
	// Run starts internal loop that handles updates from policies.
	Run(<-chan struct{})
}

// Endpoint implements Interface.
type Enforcer struct {
	// tenant cache provides updates for romana tenants.
	tenantCache tenantCache.Interface

	// tenantUpdate holds hash associated with last update of tenant cache.
	tenantUpdate string

	// policy cache provides updates for romana policies.
	policyCache policyCache.Interface

	// policyUpdate holds hash associated with last update of policy cache.
	policyUpdate string

	// provides access to romana network configuration required to translate
	// policies.
	netConfig firewall.NetConfig

	// Delay between main loop runs.
	ticker <-chan time.Time

	// Used to pause main loop.
	paused bool

	// exec used to apply iptables policies.
	exec utilexec.Executable

	// attempt to refresh policies every refreshSeconds.
	refreshSeconds int
}

// New returns new policy enforcer.
func New(tenantCache tenantCache.Interface, policyCache policyCache.Interface, network firewall.NetConfig, exec utilexec.Executable, refreshSeconds int) Interface {
	return &Enforcer{tenantCache: tenantCache, policyCache: policyCache, netConfig: network, exec: exec, refreshSeconds: refreshSeconds}
}

// Run implements Interface.  It reads notifications
// from the policy cache and from the tenant cache,
// when either cache chagned re-renders all iptables rules.
func (a *Enforcer) Run(stop <-chan struct{}) {
	log.Trace(trace.Public, "Policy enforcer Run()")

	tenants := a.tenantCache.Run(stop)
	policies := a.policyCache.Run(stop)
	iptables := &iptsave.IPtables{}
	a.ticker = time.Tick(time.Duration(a.refreshSeconds) * time.Second)
	a.paused = false

	go func() {
		for {
			select {
			case <-a.ticker:
				log.Trace(4, "Policy enforcer tick started")
				if a.paused {
					log.Tracef(5, "Policy enforcer tick skipped due to pause")
					continue
				}

				if a.policyUpdate == "" && a.tenantUpdate == "" {
					log.Tracef(5, "Policy enforcer tick skipped due no updates, hash=%s and policy hash=%s", a.tenantUpdate, a.policyUpdate)
					continue
				}

				iptables = renderIPtables(a.tenantCache, a.policyCache, a.netConfig)
				cleanupUnusedChains(iptables, a.exec)
				if ValidateIPtables(iptables, a.exec) {
					if err := ApplyIPtables(iptables, a.exec); err != nil {
						log.Errorf("iptables-restore call failed %s", err)
					}
					log.Tracef(6, "Applied iptables rules\n%s", iptables.Render())

				} else {
					log.Tracef(6, "Failed to validate iptables\n%s%n", iptables.Render())
				}
				a.policyUpdate = ""
				a.tenantUpdate = ""

			case hash := <-tenants:
				log.Trace(4, "Policy enforcer receives update from tenant cache hash=%s", hash)
				a.tenantUpdate = hash

			case hash := <-policies:
				log.Trace(4, "Policy enforcer receives update from policy cache hash=%s", hash)
				a.policyUpdate = hash

			case <-stop:
				log.Infof("Policy enforcer stopping")
				return
			}
		}
	}()
}

// Pause main loop.
func (a *Enforcer) Pause() {
	a.paused = true
}

// Continue main loop.
func (a *Enforcer) Continue() {
	a.paused = false
}

// renderIPtables creates iptables rules for all romana policies in policy cache
// except the ones which depends on non-existend tenant/segment.
func renderIPtables(tenantCache tenantCache.Interface, policyCache policyCache.Interface, netConfig firewall.NetConfig) *iptsave.IPtables {
	log.Trace(trace.Private, "Policy enforcer in renderIPtables()")

	// Make empty iptables object.
	iptables := iptsave.IPtables{
		Tables: []*iptsave.IPtable{
			&iptsave.IPtable{
				Name: "filter",
			},
		},
	}

	makeBase(&iptables)
	makeTenantRules(tenantCache, netConfig, &iptables)
	makePolicies(policyCache, netConfig, &iptables)

	return &iptables
}

// makeBase populates iptables with romana chains that do not depend on presence
// if any external resource like tenant and policy chains do.
func makeBase(iptables *iptsave.IPtables) {
	// For now our policies only exist in a filter tables so we don't care
	// for other tables.
	filter := iptables.TableByName("filter")
	filter.Chains = MakeBaseRules()

}

// makeTenantRules populates tenant/segment rules into the provided
// iptables object.
func makeTenantRules(tenantCache tenantCache.Interface, netConfig firewall.NetConfig, iptables *iptsave.IPtables) {
	log.Trace(trace.Private, "Policy enforcer in makeTenantRules()")

	// For now our policies only exist in a filter tables so we don't care
	// for other tables.
	filter := iptables.TableByName("filter")

	tenants := tenantCache.List()

	log.Tracef(5, "Policy enforcer received %d tenants from tenant cache", len(tenants))
	for _, tenant := range tenants {
		// :ROMANA-FW-T2
		tenantIngressChain := EnsureChainExists(filter, MakeTenantIngressChainName(tenant))

		// -A ROMANA-FORWARD-IN -m u32 --u32 "0x10&0xff00f000=0xa002000" -j ROMANA-FW-T2
		ingressChain := filter.ChainByName(firewall.ChainNameEndpointIngress)
		if ingressChain == nil {
			// should never get there.
			panic("Ingress chain doesn't exist, base rules aren't rendered corretly")
		}
		InsertNormalRule(ingressChain, MakeIngressTenantJumpRule(tenant, netConfig))
		log.Tracef(6, "Policy enforcer processes tenants %s with %d segments", tenant.Name, len(tenant.Segments))

		for _, segment := range tenant.Segments {
			// :ROMANA-T2-S0
			segmentChain := EnsureChainExists(filter, MakeSegmentPolicyChainName(tenant.NetworkID, segment.NetworkID))

			// -A ROMANA-FW-T2 -m u32 --u32 "0x10&0xff00ff00=0xa002000" -j ROMANA-T2-S0
			InsertNormalRule(tenantIngressChain, MakeSegmentPolicyJumpRule(tenant, segment, netConfig))

			// -A ROMANA-T2-S0 -m comment --comment POLICY_CHAIN_FOOTER -j RETURN
			segmentChain.AppendRule(MakePolicyChainFooterRule())
		}

		// :ROMANA-T2-W
		tenantWideChain := EnsureChainExists(filter, MakeTenantWideIngressChainName(tenant.NetworkID))
		// -A ROMANA-T2-W -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		tenantWideChain.InsertRule(0, MakeConntrackEstablishedRule())
		tenantWideChain.AppendRule(MakePolicyChainFooterRule())
		// -A ROMANA-T2-W -m comment --comment POLICY_CHAIN_FOOTER -j RETURN
		// -A ROMANA-FW-T2 -j ROMANA-T2-W
		InsertNormalRule(tenantIngressChain, MakeTenantWidePolicyJumpRule(tenant))
	}
}

// makePolicies populates policy related rules into the iptables.
func makePolicies(policyCache policyCache.Interface, netConfig firewall.NetConfig, iptables *iptsave.IPtables) {
	log.Trace(trace.Private, "Policy enforcer in makePolicies()")

	// For now our policies only exist in a filter tables so we don't care
	// for other tables.
	filter := iptables.TableByName("filter")

	policies := policyCache.List()

	for _, policy := range policies {
		log.Tracef(5, "Policy enforcer rendering policy %s", policy.Name)

		policyActive := false

		for _, target := range policy.AppliedTo {
			// This branch covers for situation when
			// tenant doesn't exist any more but there are
			// still policies related to that tenant.
			// We test tenant/segment existance for each target
			// and insert jumps only when needed.

			if targetChain, ok := targetExists(target, iptables); ok {
				InsertNormalRule(targetChain, MakeSimpleJumpRule(MakeRomanaPolicyName(policy)))

				log.Tracef(6, "Policy enforcer rendered target %v for policy %s.", target, policy.Name)

				policyActive = true
			} else {
				log.Tracef(6, "Policy enforcer skipped  target %v for policy %s.", target, policy.Name)
			}
		}

		// Render policy rules only if at least one target exists.
		if policyActive {

			policyChain := EnsureChainExists(filter, MakeRomanaPolicyName(policy))

			for ingressNum, ingress := range policy.Ingress {
				log.Tracef(6, "Policy enforcer renders ingress %v from policy %s", ingress, policy.Name)

				// Make ingress chain
				// -A ROMANA-P-d73a173e1f52-IN_<ingressNum>
				ingressIndexChainName := MakeRomanaPolicyIngressName(policy, ingressNum)
				policyIngressChain := EnsureChainExists(filter, ingressIndexChainName)

				for _, peer := range ingress.Peers {
					_ = peer
					// render peer
					// -A ROMANA-P-d73a173e1f52_ -m u32 --u32 "0xc&0xff00ff00=0xa002100" -j ROMANA-P-d73a173e1f52-IN_1
					InsertNormalRule(policyChain, MakePolicyIngressJump(peer, ingressIndexChainName, netConfig))
				}

				for _, rule := range ingress.Rules {
					// render rule
					// -A ROMANA-P-d73a173e1f52-IN_ -p tcp -m tcp --dport 80 -j ACCEPT
					for _, iptablesRule := range MakePolicyRule(rule) {
						InsertNormalRule(policyIngressChain, iptablesRule)
					}
				}

				// Last line of the policy
				// -A ROMANA-P-c5010560ed3e_ -m comment --comment "PolicyId=c5010560ed3e" -j RETURN
			}
		} else {
			log.Tracef(6, "Policy enforcer skips policy %s, probably no valid AppliedTo exists", policy.Name)
		}
	}
}

// targetExists checks if iptables has underlying chains for given target.
func targetExists(target common.Endpoint, iptables *iptsave.IPtables) (*iptsave.IPchain, bool) {
	log.Trace(trace.Private, "Policy enforcer in targetExists()")

	// For now our policies only exist in a filter tables so we don't care
	// for other tables.
	filter := iptables.TableByName("filter")

	var targetChainName string

	switch DetectPolicyTargetType(target) {
	case OperatorPolicyTarget:
		// for operator policies applied to traffic
		// from anywhere towards pods.
		// :ROMANA-P-c5010560ed3e_
		// -A ROMANA-OP -j ROMANA-P-c5010560ed3e_
		targetChainName = MakeOperatorPolicyChainName()

	case OperatorPolicyIngressTarget:
		// for operator policies applied to traffic
		// from pods to host.
		// :ROMANA-P-c5010560ed3e_
		// -A ROMANA-OP-IN -j ROMANA-P-c5010560ed3e_
		targetChainName = MakeOperatorPolicyIngressChainName()

	case TenantWidePolicyTarget:
		// for tenant wide policies add tenant wide jump
		// :ROMANA-P-c5010560ed3e_
		// -A ROMANA-T2-W -j ROMANA-P-a2345713hi7b_
		targetChainName = MakeTenantWideIngressChainName(*target.TenantNetworkID)

	case TenantSegmentPolicyTarget:
		// for other policies add segment to policy jump
		// :ROMANA-P-d73a173e1f52_
		// -A ROMANA-T2-S0 -j ROMANA-P-d73a173e1f52_
		targetChainName = MakeSegmentPolicyChainName(*target.TenantNetworkID, *target.SegmentNetworkID)

	default:
		panic("Uknown policy target type")
	}
	log.Tracef(6, "Detected target chain %s for target %v", targetChainName, target)

	chain := filter.ChainByName(targetChainName)
	if chain == nil {
		log.Tracef(6, "Policy enforcer fails to validate target %v, base chain doesn't exist %s", target, targetChainName)
		return nil, false
	}

	return chain, true
}

func cleanupUnusedChains(iptables *iptsave.IPtables, exec utilexec.Executable) {
	desiredFilter := iptables.TableByName("filter")

	// Load iptables rules from system.
	currentIPtables, err := LoadIPtables(exec)
	if err != nil {
		log.Errorf("Failed to load current iptables (%s), can not remove old chains", err)
		return
	}

	currentFilter := currentIPtables.TableByName("filter")
	if currentFilter == nil {
		log.Errorf("Failed to load current iptables (No filter table), can not remove old chains")
	}

	var romanaChainsInCurrentTables []string
	for _, currentChain := range currentFilter.Chains {
		if strings.HasPrefix(currentChain.Name, "ROMANA-") {
			romanaChainsInCurrentTables = append(romanaChainsInCurrentTables, currentChain.Name)
		}
	}

	for _, currentChain := range romanaChainsInCurrentTables {
		log.Tracef(5, "In cleanupUnusedChains, testing is %s exists in desired state", currentChain)
		desiredChain := desiredFilter.ChainByName(currentChain)
		if desiredChain == nil {
			log.Tracef(6, "In cleanupUnusedChains, scheduling chain %s for deletion", currentChain)
			desiredChain := iptsave.IPchain{Name: currentChain, Policy: "-", RenderState: iptsave.RenderDeleteRule}
			desiredFilter.Chains = append(desiredFilter.Chains, &desiredChain)
		}
	}
}
