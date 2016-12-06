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

// IPTsave is a library that provides IPtables type that can read
// iptables-save output and create a tokenized representation
// of it. Also it can render current tree into output suiteable
// for iptables-restore.
package iptsave

import (
	"bufio"
	"fmt"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
	"io"
)

var BuiltinChains = []string{"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}

// IPtables represents iptables configuration.
type IPtables struct {
	Tables      []*IPtable
	currentRule *IPrule
}

// lastTable returns pointer to the last IPtable in IPtables.
func (i *IPtables) lastTable() *IPtable {
	log.Trace(trace.Private, "In lastTable()")
	if len(i.Tables) == 0 {
		return nil
	}

	t := i.Tables[len(i.Tables)-1]
	log.Trace(trace.Inside, "In lastTable returning with ", t.Name)
	return t
}

// TableByName returns pointer to the IPtable with corresponding name.
// e.g. iptables "filter" table.
func (i *IPtables) TableByName(name string) *IPtable {
	for tn, t := range i.Tables {
		if t.Name == name {
			return i.Tables[tn]
		}
	}
	return nil
}

// IPtable represents table in iptables.
type IPtable struct {
	Name   string
	Chains []*IPchain
}

func (it IPtable) String() string {
	return it.Name
}

// IPtables save-restore format for IPtable
//
// --------------------------------------------+---------
// *filter                                     |
// :Chain1                                     | Header
// :Chain2                                     |
// --------------------------------------------+---------
// -A Chain1 -m ruleMatch -j ruleAction        | Rules
// -A Chain2 -m ruleMatch -j ruleAction        |
// --------------------------------------------+---------
// *COMMIT                                     | Footer

// Renders header of iptables table.
func (it IPtable) RenderHeader() string {
	res := fmt.Sprintf("*%s\n", it.String())
	for _, chain := range it.Chains {
		res += fmt.Sprintf("%s\n", chain.RenderHeader())
	}

	return res
}

// Renders footer of iptables table.
func (it IPtable) RenderFooter() string {
	var res string
	for _, chain := range it.Chains {
		res += chain.RenderFooter()
	}

	return fmt.Sprintf("%sCOMMIT\n", res)
}

// lastChain returns pointer to the last IPchain in IPtable.
func (i *IPtable) lastChain() *IPchain {
	log.Trace(trace.Private, "In lastChain()")
	if len(i.Chains) == 0 {
		return nil
	}

	c := i.Chains[len(i.Chains)-1]
	return c
}

// ChainByName looks for IPchain with corresponding name and returns a pointer to it.
func (i *IPtable) ChainByName(name string) *IPchain {
	log.Trace(trace.Private, "In ChainByName()")

	for n, c := range i.Chains {
		if c.Name == name {
			ret := i.Chains[n]
			return ret
		}
	}

	return nil
}

// IPchain represents a chain in iptables.
type IPchain struct {
	Name     string
	Policy   string
	Counters string
	Rules    []*IPrule
}

// RenderHeader returns string representation of chains header
// e.g. :MYCHAIN ACCEPT [0:0]
func (ic IPchain) RenderHeader() string {
	return fmt.Sprintf(":%s %s %s", ic.Name, ic.Policy, ic.Counters)
}

// RenderFooter returns string representation of the rules in the chain
// e.g.
// -A MYCHAIN <match> -j <action>
// -D MYCHAIN <othermatch> -j <otheraction)
func (ic IPchain) RenderFooter() string {
	var res string
	for _, rule := range ic.Rules {
		res += fmt.Sprintf("%s %s %s\n", rule.RenderState, ic.Name, rule)
	}

	return res
}

func (ic IPchain) String() string {
	return fmt.Sprintf("%s\n%s", ic.RenderHeader(), ic.RenderFooter())
}

// lastRule returns pointer to the last IPrule in IPchain.
func (i *IPchain) lastRule() *IPrule {
	if len(i.Rules) == 0 {
		return nil
	}

	r := i.Rules[len(i.Rules)-1]
	return r
}

// InsertRule inserts new rule into the chain at given index.
// If index is larger then size of rules slice, this method will append the rule.
func (ic *IPchain) InsertRule(index int, rule *IPrule) {
	if index > len(ic.Rules) {
		ic.Rules = append(ic.Rules, rule)
	} else {
		ic.Rules = append(ic.Rules, &IPrule{})
		copy(ic.Rules[index+1:], ic.Rules[index:])
		ic.Rules[index] = rule
	}
}

// AppendRule appends new rule to the chain.
func (ic *IPchain) AppendRule(rule *IPrule) {
	ic.Rules = append(ic.Rules, rule)
}

// DeleteRule appends new rule to the chain and sets rule render state to Delete.
func (ic *IPchain) DeleteRule(rule *IPrule) {
	rule.RenderState = RenderDeleteRule
	ic.Rules = append(ic.Rules, rule)
}

// RuleInChain tests if the chain contains given rule.
func (ic IPchain) RuleInChain(rule *IPrule) bool {
	for _, r := range ic.Rules {
		if r.String() == rule.String() {
			return true
		}
	}
	return false
}

// IsBuiltin returns true if chain is one of builtin chains.
func (ic IPchain) IsBuiltin() bool {
	for _, builtin := range BuiltinChains {
		if ic.Name == builtin {
			return true
		}
	}
	return false
}

// IPrule represents a rule in iptables.
type IPrule struct {
	RenderState RenderState

	// From iptables man page.
	// rule-specification = [matches...] [target]
	// match = -m matchname [per-match-options]
	Match  []*Match
	Action IPtablesAction
}

type RenderState int

const (
	RenderAppendRule RenderState = 0
	RenderDeleteRule RenderState = 1
)

func (r RenderState) String() string {
	var res string
	switch r {
	case RenderAppendRule:
		res = "-A"
	case RenderDeleteRule:
		res = "-D"
	default:
		res = "Unkown rule render state"
	}

	return res
}

func (ir IPrule) String() string {
	var res string
	for _, match := range ir.Match {
		res += fmt.Sprintf("%s ", match.String())
	}

	res += ir.Action.String()
	return res
}

// Match is a string representation of a simple boolean expressio in
// iptables terms.
// e.g. "-o eth1"
//      "-m comment --comment HelloWorld"
//      "! -p tcp --dport 80"
type Match struct {
	Negated bool
	Body    string
}

func (m Match) String() string {
	var format string
	if m.Negated {
		format = "! %s"
	} else {
		format = "%s"
	}

	// TODO lexer is grabbing extra space after each match
	// item in iptables rule
	// current method cuts last character off to account for this.
	var body string
	if (len(m.Body) > 1) && (m.Body[len(m.Body)-1] == byte(' ')) {
		body = m.Body[:len(m.Body)-1]
	} else {
		body = m.Body
	}

	return fmt.Sprintf(format, body)
}

// IPtablesAction represents an action in iptables rule.
// e.g. "-j DROP"
//      "-j DNAT --to-destination 1.2.3.4"
type IPtablesAction struct {
	Type ActionType
	Body string
}

func (ia IPtablesAction) String() string {
	return fmt.Sprintf("-j %s", ia.Body)
}

// IPtablesComment represents a comment in iptables.
type IPtablesComment string

// Parse prepares input stream, initializes lexer and launches a parse loop.
func (i *IPtables) Parse(input io.Reader) {
	bufReader := bufio.NewReader(input)
	lexer := newLexer(bufReader)
	i.parseLoop(lexer)
}

// parseLoop extracts items from input stream and passes them to the parser.
func (i *IPtables) parseLoop(lexer *Lexer) {
	for {
		item := lexer.NextItem()
		i.parseItem(item)

		if item.Type == ItemError || item.Type == ItemEOF {
			break
		}
	}
}

// parseItem installs given item in its appropriate place in IPtables.Tables tree.
func (i *IPtables) parseItem(item Item) {
	switch item.Type {
	case itemComment:
		// Ignore comment items.
		return
	case itemTable:
		// If item is a table, initialize a new Itable.
		i.Tables = append(i.Tables, &IPtable{Name: item.Body})
	case itemChain:
		// If item is a chain, add a new chain to the last table.
		table := i.lastTable()
		if table == nil {
			panic("Chain before table")
		} // TODO crash here

		log.Tracef(trace.Inside, "In ParseItem adding chain %s to the table %s", item.Body, table.Name)

		table.Chains = append(table.Chains, &IPchain{Name: item.Body})
	case itemChainPolicy:
		// If item is a chain policy, set a policy for the last chain.
		table := i.lastTable()

		log.Tracef(trace.Inside, "In ParseItem table %s has %d chains", table.Name, len(table.Chains))

		chain := table.lastChain()
		if table == nil || chain == nil {
			panic("Chain policy before table/chain")
		} // TODO crash here

		chain.Policy = item.Body
	case itemChainCounter:
		// If item is a chain counter, set a chain counter for the last chain.
		table := i.lastTable()
		chain := table.lastChain()
		if table == nil || chain == nil {
			panic("Chain policy before table/chain")
		} // TODO crash here

		chain.Counters = item.Body
	case itemCommit:
		// Ignore COMMIT items.
		return // TODO, ignored for now, should probably be in the model
	case itemRule:
		// If item is a rule, add a new rule in to the proper chain,
		// and initialize i.currentRule.
		table := i.lastTable()
		chain := table.ChainByName(item.Body)
		if table == nil || chain == nil {
			panic("Rule before table/chain")
		} // TODO crash here

		newRule := new(IPrule)
		chain.Rules = append(chain.Rules, newRule)

		i.currentRule = newRule
	case itemRuleMatch:
		// If item is a rule match, add new match to the current rule.
		if i.currentRule == nil {
			panic("RuleMatch before table/chain/rule")
		} // TODO crash here

		i.currentRule.Match = append(i.currentRule.Match, &Match{Body: item.Body})
	case itemAction:
		// If item is a rule action, add a new target to the current rule.
		if i.currentRule == nil {
			panic("RuleMatch before table/chain/rule")
		} // TODO crash here
		i.currentRule.Action = IPtablesAction{Body: item.Body}

	}

	return
}

// Render produces iptables-restore compatible representation of current structure.
func (i *IPtables) Render() string {
	var result string

	for _, table := range i.Tables {
		result += table.RenderHeader()
		result += table.RenderFooter()
	}

	return result
}

// MergeTables merges source IPtable into destination IPtable,
// returns a list of chains with only rules from source table
// that were propagated into destination table.
func MergeTables(dstTable, srcTable *IPtable) []*IPchain {
	var returnChains []*IPchain
	var newChains []*IPchain
	var newChainFound bool

	// Walk through source and look for corresponding
	// dest chain. If dest chain exists, merge them,
	// otherwise add whole source chain to the dest table.
	for srcChainNum, srcChain := range srcTable.Chains {
		newChainFound = true
		for dstChainNum, dstChain := range dstTable.Chains {
			if dstChain.Name == srcChain.Name {
				newChainFound = false
				var newRules []*IPrule

				log.Tracef(trace.Inside, "In MergeTables, merging chain %s into table %s", srcChain.Name, dstTable.Name)

				// iptables-restore with --noflush flag works differently with
				// default builtin chains and user-defined chains.
				// When builtin chains with --noflush will not be flushed, user defined chains will, regardles
				// of the flag (at least in v1.4.21), so different merge strategies are needed.
				if dstChain.IsBuiltin() {
					newRules = MergeChains(dstTable.Chains[dstChainNum], srcTable.Chains[srcChainNum])
				} else {
					newRules = MergeUserChains(dstTable.Chains[dstChainNum], srcTable.Chains[srcChainNum])
				}

				// Make new chain similar to current source but with
				// rules returned by mergeChain, use it for return.
				returnChains = append(returnChains, &IPchain{Name: srcChain.Name, Policy: srcChain.Policy, Rules: newRules})
			}
		}

		if newChainFound {
			log.Tracef(trace.Inside, "In MergeTables, adding chain %s into table %s", srcChain.Name, dstTable.Name)
			newChains = append(newChains, srcTable.Chains[srcChainNum])
		}
	}
	dstTable.Chains = append(dstTable.Chains, newChains...)

	// Making sure that we are returning new IPchain structs
	// and not pointers to the original source chains.
	for _, c := range newChains {
		returnChains = append(returnChains, &IPchain{Name: c.Name, Policy: c.Policy, Rules: c.Rules})
	}
	return returnChains
}

// MergeUserChains merges rules from the source chain into the destination chain
// produces list of rules that combines rules from both chains with order
// preserved as much as possible.
func MergeUserChains(dstChain, srcChain *IPchain) []*IPrule {
	var retRules []*IPrule
	dstLen := len(dstChain.Rules)
	srcLen := len(srcChain.Rules)

	// if one chain is empty then other chain is a result of the merge
	if srcLen == 0 {
		return dstChain.Rules
	}
	if dstLen == 0 {
		return srcChain.Rules
	}

	maxLen := 0
	if dstLen <= srcLen {
		maxLen = srcLen
	} else {
		maxLen = dstLen
	}

	// Merge strategy is to walk both rule lists at same time and compare the rules at same position
	// if rules match then one of them added to the result, otherwise both are.
	for i := 0; i < maxLen; i++ {
		if i <= dstLen && i <= srcLen {
			log.Tracef(trace.Inside, "In MergeUserTables, counter=%d, src table len=%d, dst table len=%d", i, srcLen, dstLen)
			if dstChain.Rules[i].String() == srcChain.Rules[i].String() {
				retRules = append(retRules, dstChain.Rules[i])
			} else {
				retRules = append(retRules, dstChain.Rules[i])
				retRules = append(retRules, srcChain.Rules[i])

			}
		} else if i <= dstLen {
			retRules = append(retRules, dstChain.Rules[i])
		} else if i <= srcLen {
			retRules = append(retRules, srcChain.Rules[i])
		} else {
			// Should never get here.
			panic(fmt.Sprintf("Unexpected state in MergeUserChains, counter=%d, source len=%d, dst len=%d", i, srcLen, dstLen))
		}
	}

	return retRules
}

// MergeChains merges source IPchain into destination IPchain,
// returns a list of rules that were added.
func MergeChains(dstChain, srcChain *IPchain) []*IPrule {
	// Merging strategy here is to walk through
	// unique source rules in reverse order and insert them
	// on top of the destination.

	_, uniqSrc, _ := DiffRules(dstChain.Rules, srcChain.Rules)

	var currentRule *IPrule
	srcLength := len(uniqSrc)

	for sn, _ := range uniqSrc {
		currentRule = uniqSrc[srcLength-sn-1]
		dstChain.InsertRule(0, currentRule)
	}

	return uniqSrc
}

// removeRuleFromList removes IPrule from the list of IPrules
// by its id, returns new list.
func removeRuleFromList(index int, dst []*IPrule) []*IPrule {
	copy(dst[index:], dst[index+1:])
	dst[len(dst)-1] = nil
	dst = dst[:len(dst)-1]

	return dst
}

// DiffRules compares 2 lists of iptables rules and returns 3 new lists,
// 1. return argument, rules that only found in first list
// 2. return argument, rules that only found in second list
// 3. return argumant, rules that found in bouth input lists
func DiffRules(dstRules, srcRules []*IPrule) (uniqDest, uniqSrc, common []*IPrule) {
	var unique bool

	for sn, srcRule := range srcRules {
		unique = true

		for dn, dstRule := range dstRules {
			if dstRule.String() == srcRule.String() {
				common = append(common, dstRules[dn])
				unique = false
				break
			}
		}

		if unique {
			uniqSrc = append(uniqSrc, srcRules[sn])
		}
	}

	for dn, dstRule := range dstRules {
		unique = true

		for _, commonRule := range common {
			if dstRule.String() == commonRule.String() {
				unique = false
				break
			}
		}

		if unique {
			uniqDest = append(uniqDest, dstRules[dn])
		}
	}

	return
}

// ParseRule takes single iptables rule and
// returns new IPchain with single IPrule.
func ParseRule(input io.Reader) *IPchain {
	chain := &IPchain{}

	lexer := newLexer(bufio.NewReader(input))
	lexer.state = stateInRule
	for {
		item := lexer.NextItem()

		if item.Type == ItemError || item.Type == ItemEOF {
			break
		}

		chain.parseRule(item)
	}

	return chain
}

// parseRule initializes IPchain with name and assembles a rule
// in the chain out of items.
func (c *IPchain) parseRule(item Item) error {
	switch item.Type {
	case itemRule:
		// If item is a beginning of a new rule then use
		// chain name from the rule to initialize current IPchain.
		c.Name = item.Body

	case itemRuleMatch:
		// If item is a rule match then add a new match to the rule
		// in IPchain and initialize currentRule.

		// If chain name is not initialized yet it means we are getting,
		// invalid rule. Chain name always a first item of the rule.
		if c.Name == "" {
			panic("Rule match before chain name")
		}

		if len(c.Rules) == 0 {
			c.Rules = append(c.Rules, &IPrule{})
		}

		currentRule := c.Rules[0]

		currentRule.Match = append(currentRule.Match, &Match{Body: item.Body})
	case itemAction:
		// If item is a rule action then add a new action to the currentRule.

		// If chain name is not initialized yet it means we are getting,
		// invalid rule. Chain name always a first item of the rule.
		if c.Name == "" {
			panic("Rule match before chain name")
		}

		if len(c.Rules) == 0 {
			c.Rules = append(c.Rules, &IPrule{})
		}

		currentRule := c.Rules[0]

		action := IPtablesAction{Body: item.Body}
		action.detectActionType()
		currentRule.Action = action
	default:
		panic("Unexpected item type during rule parsing")
	}
	return nil

}

type ActionType int

const (
	ActionDefault ActionType = iota
	ActionOther
)

// detectActionType detects if action is one of iptables reserved keywords
// or it is a jump to a use-chain.
func (ia *IPtablesAction) detectActionType() {
	defaultActions := []string{"DROP", "ACCEPT", "RETURN", "QUEUE", "NFQUEUE", "REJECT", "LOG", "MARK", "MASQUERADE"}
	ia.Type = ActionOther

	for _, action := range defaultActions {
		if action == ia.Body {
			ia.Type = ActionDefault
			return
		}
	}
}
