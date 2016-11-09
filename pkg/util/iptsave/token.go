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
package iptsave

import (
	"fmt"
)

type Item struct {
	Type ItemType
	Body string
}

type ItemType int

const (
	ItemError ItemType = iota
	ItemEOF
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
	case ItemError:
		return fmt.Sprintf("Error")
	case ItemEOF:
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
