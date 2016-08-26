package iptsave

import (
	"github.com/golang/glog"
	"bufio"
	"io"
	"fmt"
)

// IPtables represents iptables configuration.
type IPtables struct {
	Tables []*IPtable
	currentRule *IPrule
}

// lastTable return pointer to the last IPtable in IPtables.
func (i *IPtables) lastTable() *IPtable {
	glog.V(1).Info("In lastTable()")
	if len(i.Tables) == 0 { return nil }

	t := i.Tables[len(i.Tables)-1]
	glog.V(2).Info("In lastTable returning with ", t.Name)
	return t
}

// tableByName returns pointer to the IPtable with corresponding name
func (i *IPtables) TableByName(name string) *IPtable {
	for tn, t := range i.Tables {
		if t.Name == name {
			return i.Tables[tn]
		}
	}
	return nil
}


// IPtable represents tables in iptables.
type IPtable struct {
	Name string
	Chains []*IPchain
}

func (it IPtable) String() string {
	return it.Name
}

func (it IPtable) RenderHeader() string {
	res := fmt.Sprintf("*%s\n", it.String())
	for _, chain := range it.Chains {
		res += fmt.Sprintf("%s\n", chain.RenderHeader())
	}

	return res
}

func (it IPtable) RenderFooter () string {
	var res string
	for _, chain := range it.Chains {
		res += chain.RenderFooter()
	}

	return fmt.Sprintf("%sCOMMIT\n", res)
}

// lastChain returns pointer to the last IPchain in IPtable.
func (i *IPtable) lastChain() *IPchain {
	glog.V(1).Info("In lastChain()")
	if len(i.Chains) == 0 { return nil }

	c := i.Chains[len(i.Chains)-1]
	return c
}

// ChainByName looks for IPchain with corresponding name and returns a pointer to it.
func (i *IPtable) ChainByName(name string) *IPchain {
	glog.V(1).Info("In ChainByName()")

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
	Name string
	Policy string
	Counters string
	Rules []*IPrule
}

// RenderHeader returns string representation of chains header
// e.g. :MYCHAIN ACCEPT [0:0]
func (ic IPchain) RenderHeader() string {
	return fmt.Sprintf(":%s %s %s", ic.Name, ic.Policy, ic.Counters)
}

// RenderFooter returns string representation of the rules in the chain
// e.g.
// -A MYCHAIN <match> -j <action>
// -A MYCHAIN <othermatch> -j <otheraction)
func (ic IPchain) RenderFooter() string {
	var res string
	for _, rule := range ic.Rules {
		res += fmt.Sprintf("-A %s %s\n", ic.Name, rule.String())
	}

	return res
}

func (ic IPchain) String() string {
	return fmt.Sprintf("%s\n%s", ic.RenderHeader(), ic.RenderFooter())
}

// lastRule returns pointer to the last IPchain in IPtable.
func (i *IPchain) lastRule() *IPrule {
	if len(i.Rules) == 0 { return nil }

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

// RuleInChain tests if the chain contains given rule.
func (ic IPchain) RuleInChain(rule *IPrule) bool {
	for _, r := range ic.Rules {
		if r.String() == rule.String() {
			return true
		}
	}
	return false
}

// IPrule represents a rule in iptables.
type IPrule struct {
	Match []*Match
	Action  IPtablesAction
}

func (ir IPrule) String() string {
	var res string
	for _, match := range ir.Match {
		res += fmt.Sprintf("%s ", match.String())
	}

	res += ir.Action.String()
	return res
}

// Match represents a match in iptables rule.
type Match struct {
	Negated bool
	Body string
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
	if len(m.Body) > 1 {
		body = m.Body[:len(m.Body)-1]
	} else {
		body = m.Body
	}

	return fmt.Sprintf(format, body)
}

// IPtablesAction represents an action in iptables rule.
type IPtablesAction struct {
	Type string
	Body string
}

func (ia IPtablesAction) String() string {
	return fmt.Sprintf("-j %s", ia.Body)
}

// IPtablesComment represents a comment in iptables.
type IPtablesComment string

// Parse reads iptables configuration from input.
func (i *IPtables) Parse(input io.Reader) {
	bufReader := bufio.NewReader(input)	
	lexer := newLexer(bufReader)
	i.parse(lexer)
}

func (i *IPtables) parse(lexer *Lexer) {
	for {
		item := lexer.NextItem()
		// fmt.Printf("Discovered item of type %s with body %s \n", item.Type, item.Body)
		i.parseItem(item)

		if item.Type == ItemError || item.Type == ItemEOF {
			break
		}
	}
}

func (i *IPtables) parseItem(item Item) {
	switch item.Type {
	case itemComment:
		return
	case itemTable:
		i.Tables = append(i.Tables, &IPtable{Name: item.Body})
	case itemChain:
		table := i.lastTable()
		if table == nil { panic("Chain before table") } // TODO crash here

		glog.V(1).Infof("In ParseItem adding chain %s to the table %s", item.Body, table.Name)

		table.Chains = append(table.Chains, &IPchain{Name: item.Body})
	case itemChainPolicy:
		table := i.lastTable()

		glog.V(2).Infof("In ParseItem table %s has %d chains", table.Name, len(table.Chains))

		chain := table.lastChain()
		if table == nil || chain == nil { panic("Chain policy before table/chain") } // TODO crash here

		chain.Policy = item.Body
	case itemChainCounter:
		table := i.lastTable()
		chain := table.lastChain()
		if table == nil || chain == nil { panic("Chain policy before table/chain") } // TODO crash here

		chain.Counters = item.Body
	case itemCommit:
		return // TODO, ignored for now, should probably be in the model
	case itemRule:
		table := i.lastTable()
		chain := table.ChainByName(item.Body)
		if table == nil || chain == nil { panic("Rule before table/chain") } // TODO crash here

		newRule := new(IPrule)
		chain.Rules = append(chain.Rules, newRule)

		i.currentRule = newRule
	case itemRuleMatch:
		if i.currentRule == nil { panic("RuleMatch before table/chain/rule") } // TODO crash here

		i.currentRule.Match = append(i.currentRule.Match, &Match{Body: item.Body})
	case itemAction:
		if i.currentRule == nil { panic("RuleMatch before table/chain/rule") } // TODO crash here
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

// MergeTables merges source IPtable into destination IPtable
func MergeTables (dstTable, srcTable *IPtable) {
	var newChains []*IPchain
	var newChainFound bool

	for srcChainNum, srcChain := range srcTable.Chains {
		newChainFound = true
		for dstChainNum, dstChain := range dstTable.Chains {
			if dstChain.Name == srcChain.Name {
				glog.V(3).Infof("In MergeTables, merging chain %s into table %s", srcChain.Name, dstTable.Name)
				MergeChains(dstTable.Chains[dstChainNum], srcTable.Chains[srcChainNum])
				newChainFound = false
			}
		}

		if newChainFound {
			glog.V(3).Infof("In MergeTables, adding chain %s into table %s", srcChain.Name, dstTable.Name)
			newChains = append(newChains, srcTable.Chains[srcChainNum])
		}
	}

	dstTable.Chains = append(dstTable.Chains, newChains...)
}

// MergeChains merges source IPchain into destination IPchain
func MergeChains (dstChain, srcChain *IPchain) {
	// Merging strategy here is to walk through
	// source rules in reverse order and insert them
	// on top of the destination chain if they are not already
	// in there.

	var currentRule *IPrule
	srcLength := len(srcChain.Rules)

	for sn, _ := range srcChain.Rules {
		currentRule = srcChain.Rules[srcLength - sn -1]
		if !dstChain.RuleInChain(currentRule) {
			dstChain.InsertRule(0, currentRule)
		}
	}
}
