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
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	utilexec "github.com/romana/core/agent/exec"
	"github.com/romana/core/agent/firewall"
	"github.com/romana/core/agent/iptsave"
	policyCache "github.com/romana/core/agent/policy/cache"
	tenantCache "github.com/romana/core/agent/tenant/cache"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/ipset"

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
	ticker *time.Ticker

	// Used to pause main loop.
	paused bool

	// exec used to apply iptables policies.
	exec utilexec.Executable

	// attempt to refresh policies every refreshSeconds.
	refreshSeconds int
}

// New returns new policy enforcer.
func New(tenantCache tenantCache.Interface,
	policyCache policyCache.Interface,
	network firewall.NetConfig,
	utilexec utilexec.Executable,
	refreshSeconds int) (Interface, error) {

	var err error

	if iptablesSaveBin, err = exec.LookPath("iptables-save"); err != nil {
		return nil, err
	}

	if iptablesRestoreBin, err = exec.LookPath("iptables-restore"); err != nil {
		return nil, err
	}

	return &Enforcer{
		tenantCache:    tenantCache,
		policyCache:    policyCache,
		netConfig:      network,
		exec:           utilexec,
		refreshSeconds: refreshSeconds,
	}, nil
}

// Run implements Interface.  It reads notifications
// from the policy cache and from the tenant cache,
// when either cache chagned re-renders all iptables rules.
func (a *Enforcer) Run(stop <-chan struct{}) {
	log.Trace(trace.Public, "Policy enforcer Run()")

	tenants := a.tenantCache.Run(stop)
	policies := a.policyCache.Run(stop)
	iptables := &iptsave.IPtables{}
	a.ticker = time.NewTicker(time.Duration(a.refreshSeconds) * time.Second)
	a.paused = false

	go func() {
		for {
			select {
			case <-a.ticker.C:
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
				a.ticker.Stop()
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

type BlockCache interface {
	List() []api.IPAMBlockResponse
}

// suppressItemExist suppresses an error when ipset.AddX()
// operation failes due to item already exists in collection.
func suppressItemExist(e error) error {
	if errors.Cause(e) == ipset.ErrorItemExist {
		return nil
	}
	return e
}

// makeBlockSets creates ipset configuration for policies and blocks.
func makeBlockSets(blockCache BlockCache, policyCache policyCache.Interface, hostname string) (*ipset.Ipset, error) {
	blocks := blockCache.List()
	policies := policyCache.List()
	sets := ipset.NewIpset()

	// for every policy produce 2 sets, one to match
	// incoming traffic and one to match outgoing traffic.
	for _, policy := range policies {
		srcSet, dstSet, err := makePolicySets(policy)
		if err != nil {
			return nil, err
		}

		err = sets.AddSet(srcSet)
		err = sets.AddSet(dstSet)
		if err != nil {
			return nil, err
		}
	}

	// for every block produce 2 sets
	// - tenant+segment set contains all the blocks
	// for the relevan t+s combination
	// - tenant set contains all the t+s sets for the
	// relevant tenant
	for _, block := range blocks {
		if block.Segment == "" {
			// TODO error, can't distinguish between
			// tenantSegment set and tenant set
		}

		// TODO ignore blocks for other hostnames? then what about egress?

		segmentSetName := makeTenantSetName(block.Tenant, block.Segment)
		segmentSet, _ := ipset.NewSet(segmentSetName, ipset.SetHashNet)
		err := suppressItemExist(sets.AddSet(segmentSet))
		if err != nil {
			return nil, err
		}

		memberForSegmentSet, _ := ipset.NewMember(block.CIDR.IPNet.String(), segmentSet)
		err = suppressItemExist(segmentSet.AddMember(memberForSegmentSet))
		if err != nil {
			return nil, err
		}

		tenantSetName := makeTenantSetName(block.Tenant, "")
		tenantSet, _ := ipset.NewSet(tenantSetName, ipset.SetListSet)
		err = suppressItemExist(sets.AddSet(tenantSet))
		if err != nil {
			return nil, err
		}

		memberForTenantSet, _ := ipset.NewMember(segmentSet.Name, tenantSet)
		err = suppressItemExist(tenantSet.AddMember(memberForTenantSet))
		if err != nil {
			return nil, err
		}

	}

	return sets, nil
}

func makePolicySets(policy api.Policy) (*ipset.Set, *ipset.Set, error) {
	setSrc, err := ipset.NewSet(MakeRomanaPolicyNameSetSrc(policy), ipset.SetHashNet)
	if err != nil {
		return setSrc, nil, err
	}

	setDst, err := ipset.NewSet(MakeRomanaPolicyNameSetDst(policy), ipset.SetHashNet)
	if err != nil {
		return setSrc, setDst, err
	}

	for _, ingress := range policy.Ingress {
		for _, peer := range ingress.Peers {
			if peerType := DetectPolicyPeerType(peer); peerType == PeerCIDR {
				switch policy.Direction {
				case api.PolicyDirectionEgress:
					member, err := ipset.NewMember(peer.Cidr, setDst)
					if err != nil {
						return nil, nil, err
					}
					err = suppressItemExist(setDst.AddMember(member))
					if err != nil {
						return nil, nil, err
					}
				case api.PolicyDirectionIngress:
					member, err := ipset.NewMember(peer.Cidr, setSrc)
					if err != nil {
						return nil, nil, err
					}
					err = suppressItemExist(setSrc.AddMember(member))
					if err != nil {
						return nil, nil, err
					}
				}
			}
		}
	}

	return setSrc, setDst, err
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

// makePolicies populates policy related rules into the iptables.
// TODO need to avoid rendering policies for which there is no targets on the host.
func makePolicies(policyCache policyCache.Interface, netConfig firewall.NetConfig, iptables *iptsave.IPtables) {
	log.Trace(trace.Private, "Policy enforcer in makePolicies()")

	// For now our policies only exist in a filter tables so we don't care
	// for other tables.
	// TODO makePolicyRules checks for *filter inside
	// filter := iptables.TableByName("filter")

	policies := policyCache.List()

	for _, policy := range policies {
		_ = makePolicyRules(policy, SchemePolicyOnTop, iptables)
	}
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

type RuleBlueprint struct {
	baseChain        string
	topRuleMatch     func(api.Endpoint) string
	topRuleAction    func(api.Policy) string
	secondBaseChain  func(api.Policy) string
	secondRuleMatch  func(api.Endpoint) string
	secondRuleAction func(api.Policy) string
	thirdBaseChain   func(api.Policy) string
	thirdRuleMatch   func(api.Endpoint) string
	thirdRuleAction  func(api.Policy) string
	fourthBaseChain  func(api.Policy) string
	fourthRuleMatch  func(api.Rule, string) []*iptsave.IPrule
	fourthRuleAction string
}

//go:generate go run internal/gen/main.go -data data/policy.tsv -template templates/blueprint.go_template -out blueprint.go

func makeTenantSetName(tenant, segment string) string {
	setName := fmt.Sprintf("tenant_%s", tenant)
	if segment != "" {
		setName += fmt.Sprintf("_segment_%s", segment)
	}
	return setName
}

func makeSrcTenantMatch(e api.Endpoint) string { return makeTenantMatch(e, "src") }
func makeDstTenantMatch(e api.Endpoint) string { return makeTenantMatch(e, "dst") }
func makeTenantMatch(e api.Endpoint, direction string) string {
	return fmt.Sprintf("-m set --match-set %s %s", makeTenantSetName(e.TenantID, ""), direction)
}

func makeSrcTenantSegmentMatch(e api.Endpoint) string { return makeTenantSegmentMatch(e, "src") }
func makeDstTenantSegmentMatch(e api.Endpoint) string { return makeTenantSegmentMatch(e, "dst") }
func makeTenantSegmentMatch(e api.Endpoint, direction string) string {
	return fmt.Sprintf("-m set --match-set %s %s", makeTenantSetName(e.TenantID, e.SegmentID), direction)
}

func makeSrcCIDRMatch(e api.Endpoint) string { return makeCIDRMatch(e, "s") }
func makeDstCIDRMatch(e api.Endpoint) string { return makeCIDRMatch(e, "d") }
func makeCIDRMatch(e api.Endpoint, direction string) string {
	return fmt.Sprintf("-%s %s", direction, e.Cidr)
}

func matchEndpoint(s string) func(api.Endpoint) string {
	return func(api.Endpoint) string { return s }
}
func matchPolicyString(s string) func(api.Policy) string {
	return func(api.Policy) string { return s }
}

func EnsureRules(baseChain *iptsave.IPchain, rules []*iptsave.IPrule) {
	for _, rule := range rules {
		if !baseChain.RuleInChain(rule) {
			InsertNormalRule(baseChain, rule)
		}
	}
}

func rules2list(rules ...*iptsave.IPrule) (result []*iptsave.IPrule) {
	for _, r := range rules {
		result = append(result, r)
	}
	return
}

func makePolicyRuleInDirection(policy api.Policy,
	iptablesSchemeType string,
	peer, target api.Endpoint,
	rule api.Rule,
	direction string,
	iptables *iptsave.IPtables) error {

	peerType := DetectPolicyPeerType(peer) // TODO ten/host/local/cidr
	dstType := DetectPolicyTargetType(target)

	log.Debug("makePolicyRuleInDirection #1")

	key := MakeBlueprintKey(direction, iptablesSchemeType, peerType, dstType) // TODO

	translationConfig, ok := blueprints[key]
	// log.Debugf("makePolicyRuleInDirection with key %s, ok=%t, value=%s", key, ok, translationConfig)
	if !ok {
		return errors.New("can't translate ... ")
	}

	filter := iptables.TableByName("filter")

	baseChain := EnsureChainExists(filter, translationConfig.baseChain)

	// jump from base chain to policy chain
	jumpFromBaseToPolicyRule := MakeRuleWithBody(
		translationConfig.topRuleMatch(target), translationConfig.topRuleAction(policy),
	)

	EnsureRules(baseChain, rules2list(jumpFromBaseToPolicyRule))

	secondBaseChainName := translationConfig.secondBaseChain(policy)
	secondRuleMatch := translationConfig.secondRuleMatch(target)
	secondRuleAction := translationConfig.secondRuleAction(policy)
	if secondBaseChainName != "" && secondRuleMatch != "" && secondRuleAction != "" {
		secondBaseChain := EnsureChainExists(filter, secondBaseChainName)
		jumpFromSecondChainToThirdChainRule := MakeRuleWithBody(
			secondRuleMatch, secondRuleAction,
		)

		EnsureRules(secondBaseChain, rules2list(jumpFromSecondChainToThirdChainRule))

	}

	thirdBaseChainName := translationConfig.thirdBaseChain(policy)
	thirdBaseChain := EnsureChainExists(filter, thirdBaseChainName)
	thirdRuleMatch := translationConfig.thirdRuleMatch(peer)
	thirdRuleAction := translationConfig.thirdRuleAction(policy)

	thirdRule := MakeRuleWithBody(
		thirdRuleMatch, thirdRuleAction,
	)

	EnsureRules(thirdBaseChain, rules2list(thirdRule))

	fourthBaseChainName := translationConfig.fourthBaseChain(policy)
	fourthBaseChain := EnsureChainExists(filter, fourthBaseChainName)
	fourthRuleAction := translationConfig.fourthRuleAction
	fourthRules := translationConfig.fourthRuleMatch(rule, fourthRuleAction)

	EnsureRules(fourthBaseChain, fourthRules)

	log.Debug("makePolicyRuleInDirection #3")
	return nil
}

func makePolicyRules(policy api.Policy, iptablesSchemeType string, iptables *iptsave.IPtables) error {
	log.Debugf("in makePolicyRules with %+v", policy)
	for _, target := range policy.AppliedTo {
		for _, ingress := range policy.Ingress {
			for _, peer := range ingress.Peers {
				for _, rule := range ingress.Rules {
					err := makePolicyRuleInDirection(
						policy,
						iptablesSchemeType,
						peer,
						target,
						rule,
						policy.Direction,
						iptables,
					)
					if err != nil {
						log.Errorf("Error appying %s policy to target %v and peer %v with rule %v, err=%s", policy.Direction, target, peer, rule, err)
					}
				}
			}
		}
		/* Egress via dedicated field
		for _, egress := range policy.Egress {
			for _, peer := range egress.Peers {
				for _, rule := range egress.Rules {
					_ = makePolicyRuleInDirection(
						policy,
						iptablesSchemeType,
						peer,
						target,
						rule,
						api.PolicyDirectionEgress,
						iptables,
					)
				}
			}
		}
		*/
	}
	return nil
}
