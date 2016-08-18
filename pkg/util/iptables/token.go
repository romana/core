package main

import (
	"fmt"
)

type Item struct {
	Type ItemType
	Body string
}

type ItemType int

const (
	itemError ItemType = iota
	itemEOF
	itemComment
	itemTable
	itemChain
	itemChainPolicy
	itemChainCounter
	itemRule
	itemRuleMatch
	itemModule
	itemAction
	itemOptions
	itemCommit
)

func (i ItemType) String() string {
	switch i {
	case itemError:
		return fmt.Sprintf("Error")
	case itemEOF:
		return fmt.Sprintf("EOF")
	case itemComment:
		return fmt.Sprintf("Comment")
	case itemTable:
		return fmt.Sprintf("Table")
	case itemChain:
		return fmt.Sprintf("Chain")
	case itemChainPolicy:
		return fmt.Sprintf("ChainPolicy")
	case itemChainCounter:
		return fmt.Sprintf("ChainCounter")
	case itemRule:
		return fmt.Sprintf("Rule")
	case itemRuleMatch:
		return fmt.Sprintf("RuleMatch")
	case itemModule:
		return fmt.Sprintf("Module")
	case itemAction:
		return fmt.Sprintf("Action")
	case itemOptions:
		return fmt.Sprintf("Options")
	case itemCommit:
		return fmt.Sprintf("Commit")
	default:
		return fmt.Sprintf("Unknown item")
	}
}
