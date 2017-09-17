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
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	utilexec "github.com/romana/core/agent/exec"
	"github.com/romana/core/agent/firewall"
	"github.com/romana/core/agent/internal/cache/policycache"
	"github.com/romana/core/agent/internal/controllers/policycontroller"
	"github.com/romana/core/agent/iptsave"
	"github.com/romana/core/agent/policy/hasher"
	tenantCache "github.com/romana/core/agent/tenant/cache"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/ipset"

	log "github.com/romana/rlog"
)

// Interface defines policy enforcer behavior.
type Interface interface {
	// Run starts internal loop that handles updates from policies.
	Run(context.Context)
}

// Endpoint implements Interface.
type Enforcer struct {
	policyCache policycache.Interface

	romanaClient *client.Client

	hostname string

	policyKey string

	// tenant cache provides updates for romana tenants.
	tenantCache tenantCache.Interface

	// blocksUpdate holds hash associated with last update of tenant cache.
	blocksUpdate bool

	// policy cache provides updates for romana policies.
	// policyCache policyCache.Interface

	// policyUpdate holds hash associated with last update of policy cache.
	policyUpdate bool

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
func New(policyCache policycache.Interface,
	client *client.Client,
	hostname string,
	utilexec utilexec.Executable,
	refreshSeconds int) (Interface, error) {

	var err error

	if IptablesSaveBin, err = exec.LookPath("iptables-save"); err != nil {
		return nil, err
	}

	if IptablesRestoreBin, err = exec.LookPath("iptables-restore"); err != nil {
		return nil, err
	}

	return &Enforcer{
		policyCache:    policyCache,
		romanaClient:   client,
		hostname:       hostname,
		exec:           utilexec,
		refreshSeconds: refreshSeconds,
		policyKey:      "/romana/policies",
	}, nil
}

// Run implements Interface.  It reads notifications
// from the policy cache and from the tenant cache,
// when either cache chagned re-renders all iptables rules.
func (a *Enforcer) Run(ctx context.Context) {
	log.Trace(trace.Public, "Policy enforcer Run()")

	policies, err := policycontroller.Run(ctx, a.policyKey, a.romanaClient, a.policyCache)
	if err != nil {
		panic(err)
	}

	var romanaBlocks []api.IPAMBlockResponse
	blocks, err := a.romanaClient.WatchBlocks(ctx.Done())
	if err != nil {
		panic(err)
	}

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

				if !a.policyUpdate && !a.blocksUpdate {
					log.Tracef(5, "Policy enforcer tick skipped due no updates, block update=%t and policy update=%t", a.blocksUpdate, a.policyUpdate)
					continue
				}

				if len(romanaBlocks) == 0 {
					log.Trace(5, "no blocks, skipping")
					continue
				}

				sets, err := makeBlockSets(romanaBlocks, a.policyCache, a.hostname)
				if err != nil {
					panic(err)
				}

				_, err = ipset.Flush(nil)
				if err != nil {
					panic(err)
				}

				ipsetHandle, err := ipset.NewHandle()
				if err != nil {
					panic(err)
				}

				err = ipsetHandle.Start()
				if err != nil {
					panic(err)
				}

				err = ipsetHandle.Create(sets)
				if err != nil {
					panic(err)
				}

				err = ipsetHandle.Add(sets)
				if err != nil {
					panic(err)
				}

				err = ipsetHandle.Quit()
				if err != nil {
					panic(err)
				}

				cTimout, _ := context.WithTimeout(ctx, 10*time.Second)
				err = ipsetHandle.Wait(cTimout)
				if err != nil {
					panic(err)
				}

				iptables = renderIPtables(a.policyCache, a.hostname, romanaBlocks)
				cleanupUnusedChains(iptables, a.exec)
				if ValidateIPtables(iptables, a.exec) {
					if err := ApplyIPtables(iptables, a.exec); err != nil {
						log.Errorf("iptables-restore call failed %s", err)
					}
					log.Tracef(6, "Applied iptables rules\n%s", iptables.Render())

				} else {
					log.Tracef(6, "Failed to validate iptables\n%s%n", iptables.Render())
				}
				a.policyUpdate = false
				a.blocksUpdate = false

			case blocksList := <-blocks:
				log.Trace(4, "Policy enforcer receives update from cache blocks revision=%d",
					blocksList.Revision)
				romanaBlocks = blocksList.Blocks
				a.blocksUpdate = true

			case <-policies:
				log.Trace(4, "Policy enforcer receives update from policy cache")
				a.policyUpdate = true

			case <-ctx.Done():
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

// makeBlockSets creates ipset configuration for policies and blocks.
func makeBlockSets(blocks []api.IPAMBlockResponse, policyCache policycache.Interface, hostname string) (*ipset.Ipset, error) {
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
		if err != nil {
			return nil, err
		}

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
		log.Tracef(5, "Making set for %+v", block)

		segmentSetName := makeTenantSetName(block.Tenant, block.Segment)
		segmentSet, _ := ipset.NewSet(segmentSetName, ipset.SetHashNet)
		err := ipset.SuppressItemExist(sets.AddSet(segmentSet))
		if err != nil {
			return nil, err
		}

		memberForSegmentSet, _ := ipset.NewMember(block.CIDR.IPNet.String(), segmentSet)
		err = ipset.SuppressItemExist(segmentSet.AddMember(memberForSegmentSet))
		if err != nil {
			return nil, err
		}

		tenantSetName := makeTenantSetName(block.Tenant, "")
		tenantSet, _ := ipset.NewSet(tenantSetName, ipset.SetListSet)
		err = ipset.SuppressItemExist(sets.AddSet(tenantSet))
		if err != nil {
			return nil, err
		}

		memberForTenantSet, _ := ipset.NewMember(segmentSet.Name, tenantSet)
		err = ipset.SuppressItemExist(tenantSet.AddMember(memberForTenantSet))
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
					err = ipset.SuppressItemExist(setDst.AddMember(member))
					if err != nil {
						return nil, nil, err
					}
				case api.PolicyDirectionIngress:
					member, err := ipset.NewMember(peer.Cidr, setSrc)
					if err != nil {
						return nil, nil, err
					}
					err = ipset.SuppressItemExist(setSrc.AddMember(member))
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
func renderIPtables(policyCache policycache.Interface, hostname string, blocks []api.IPAMBlockResponse) *iptsave.IPtables {
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
	makePolicies(policyCache, hostname, blocks, &iptables)

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
func makePolicies(policyCache policycache.Interface, hostname string, blocks []api.IPAMBlockResponse, iptables *iptsave.IPtables) {
	log.Trace(trace.Private, "Policy enforcer in makePolicies()")

	// For now our policies only exist in a filter tables so we don't care
	// for other tables.
	// TODO makePolicyRules checks for *filter inside
	// filter := iptables.TableByName("filter")

	policies := policyCache.List()

	for _, policy := range policies {
		_ = makePolicyRules(policy, SchemePolicyOnTop, blocks, iptables)
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
	hash := hasher.HashListOfStrings([]string{setName})

	log.Debugf("In makeTenantSetName(%s, %s) out with %s", tenant, segment, "ROMANA-"+hash[:16])
	return "ROMANA-" + hash[:16]
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

func makePolicyRules(policy api.Policy, iptablesSchemeType string, blocks []api.IPAMBlockResponse, iptables *iptsave.IPtables) error {
	log.Debugf("in makePolicyRules with %+v", policy)
	for _, target := range policy.AppliedTo {
		for _, ingress := range policy.Ingress {
			for _, peer := range ingress.Peers {
				for _, rule := range ingress.Rules {
					if !targetValid(target, blocks) {
						log.Debugf("Target %s skipped for policy %s as invalid for the host", target, policy.ID)
						continue
					}
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

// targetValid validates that endpoint provided as a target refers to the known
// tenant and segment.
// Always true for non tenant types of matching.
func targetValid(target api.Endpoint, blocks []api.IPAMBlockResponse) bool {
	// if endpoint doesn't match tenant this check is irrelevant.
	if target.TenantID == "" {
		log.Debugf("target %s is valid becuase it is not a tenant match", target)
		return true
	}

	// accumulate all known segments for this tenant.
	var segments []string
	for _, block := range blocks {

		log.Debugf("in targetValid comparing block.Tenant(%s) == target.TenantID(%s) = %t", block.Tenant, target.TenantID, block.Tenant == target.TenantID)

		if block.Tenant == target.TenantID {
			segments = append(segments, block.Segment)
		}
	}

	if len(segments) == 0 {
		log.Debugf("target %s is invalid because it matches no segments", target)
		return false
	}

	if target.SegmentID == "" {
		log.Debugf("target %s is valid because it has corresponding block and doesn't match any segment", target)
		return true
	}

	for _, segment := range segments {
		log.Debugf("in targetValid comparing target.SegmentID(%s) == segment(%s) = %t", target.SegmentID, segment, target.SegmentID == segment)

		if target.SegmentID == segment {
			return true
		}
	}

	return false
}
