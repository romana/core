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

// Tests for iptsave library.
package iptsave

// Some comments on use of mocking framework in helpers_test.go.

import (
	"bufio"
	"bytes"
	"testing"
)

func makeChains() (srcChain, dstChain IPchain) {
	dstChain = IPchain{
		Name: "Dest",
		Rules: []*IPrule{
			&IPrule{Action: IPtablesAction{Body: "Common"}},
			&IPrule{Action: IPtablesAction{Body: "uniqDest"}},
			&IPrule{Action: IPtablesAction{Body: "Common2"}},
		},
	}

	srcChain = IPchain{
		Name: "Src",
		Rules: []*IPrule{
			&IPrule{Action: IPtablesAction{Body: "Common"}},
			&IPrule{Action: IPtablesAction{Body: "Common2"}},
			&IPrule{Action: IPtablesAction{Body: "UniqSrc"}},
		},
	}

	return
}

func TestDiffRules(t *testing.T) {
	srcChain, dstChain := makeChains()

	uniqDest, uniqSrc, common := DiffRules(dstChain.Rules, srcChain.Rules)

	for _, r := range uniqSrc {
		t.Logf("src --> %s\n", r)
	}

	for _, r := range uniqDest {
		t.Logf("dest --> %s\n", r)
	}

	for _, r := range common {
		t.Logf("comm --> %s\n", r)
	}

	if len(uniqSrc) != 1 {
		t.Errorf("Expecting exactly 1 entry in source chain, got %d", len(uniqSrc))
	}

	if len(uniqDest) != 1 {
		t.Errorf("Expecting exactly 1 entry in dest chain, got %d", len(uniqDest))
	}

	if len(common) != 2 {
		t.Errorf("Expecting exactly 2 entries in common chain, got %d", len(common))
	}

}

func TestMergeRules(t *testing.T) {
	srcChain, dstChain := makeChains()
	newRules := MergeChains(&dstChain, &srcChain)

	for _, r := range dstChain.Rules {
		t.Logf("new dest --> %s\n", r)
	}

	for _, r := range newRules {
		t.Logf("new rules --> %s\n", r)
	}

	if len(dstChain.Rules) != 4 {
		t.Errorf("Expecting exactly 4 entries in dest chain, got %d", len(dstChain.Rules))
	}

}

func TestRuleParser(t *testing.T) {
	rule := "MYCHAIN -p tcp --dport 55 ! -p tcp --sport 80 -j TARGET"
	reader := bufio.NewReader(bytes.NewReader([]byte(rule)))
	chain := ParseRule(reader)
	if chain.Name != "MYCHAIN" || chain.Rules[0].String() != "-p tcp --dport 55 ! -p tcp --sport 80 -j TARGET" {
		t.Errorf("%s\n%s", chain.Name, chain.Rules[0].String())
	}
}
