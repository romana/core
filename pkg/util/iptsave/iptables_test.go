package iptsave

// Some comments on use of mocking framework in helpers_test.go.

import (
	"testing"
	"bufio"
	"bytes"
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
		t.Errorf("Expecting exactly 1 entry in source chain, got %s", len(uniqSrc))
	}

	if len(uniqDest) != 1 {
		t.Errorf("Expecting exactly 1 entry in dest chain, got %s", len(uniqDest))
	}

	if len(common) != 2 {
		t.Errorf("Expecting exactly 2 entries in common chain, got %s", len(common))
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
		t.Errorf("Expecting exactly 4 entries in dest chain, got %s", len(dstChain.Rules))
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
