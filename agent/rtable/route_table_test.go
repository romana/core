// Copyright (c) 2017 Pani Networks
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

package rtable

import (
	"bytes"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

const testFileDir = "testdata"

var cleanupFlag = flag.Bool("cleanup", true, "cleanup temporary files after run")

// prepareTestFile takes a name of a test file and creates a copy of that file
// with a random name.
// It returns tmporary file name, cleanup function and an error if any.
func prepareTestFile(t *testing.T, caseFile string) (string, func()) {
	tmpFile, err := ioutil.TempFile(testFileDir, caseFile)
	if err != nil {
		t.Fatalf("failed to create tmp file %s", err)
	}
	cleanup := func() { os.Remove(tmpFile.Name()) }

	testData, err := ioutil.ReadFile(filepath.Join(testFileDir, caseFile))
	if err != nil {
		t.Fatalf("failed to read test data from %s, err=%s", caseFile, err)
	}

	err = ioutil.WriteFile(tmpFile.Name(), testData, os.ModePerm)
	if err != nil {
		t.Fatalf("failed to write data to the tmp file %s, err=%s", tmpFile.Name(), err)
	}

	return tmpFile.Name(), cleanup
}

func compareFiles(t *testing.T, caseFile, goldenFile string) bool {
	caseData, err := ioutil.ReadFile(caseFile)
	if err != nil {
		t.Fatalf("failed to read case file %s, err=%s", caseFile, err)
	}

	goldenData, err := ioutil.ReadFile(filepath.Join(testFileDir, goldenFile))
	if err != nil {
		t.Fatalf("failed to read golden file %s, err=%s", goldenFile, err)
	}

	if !bytes.Equal(caseData, goldenData) {
		return false
	}
	return true
}

func TestEnsureRouteTableName(t *testing.T) {
	cases := []struct {
		name, tableName, caseFile, goldenFile string
		tableId                               int
		expect                                bool
	}{
		{"append line to file", "romana", "rt_tables.case1", "rt_tables.golden", 10, true},
		{"don't append if line is there already", "romana", "rt_tables.golden", "rt_tables.golden", 10, true},
		{"append wrong line", "wrong", "rt_tables.case1", "rt_tables.golden", 99, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile, cleanup := prepareTestFile(t, tc.caseFile)
			defer func() {
				if *cleanupFlag {
					cleanup()
				}
			}()

			f, err := os.OpenFile(tmpFile, os.O_RDWR, 0644)
			if err != nil {
				t.Fatalf("failed to open tmp file err=%s", err)
			}

			err = ensureRouteTableName(f, tc.tableName, tc.tableId)
			if err != nil {
				t.Fatal(err)
			}

			if compareFiles(t, tmpFile, tc.goldenFile) != tc.expect {
				t.Fatal("unexpected result")
			}
		})
	}
}

type mockRuleHandle struct {
	ruleList  []netlink.Rule
	addedRule *netlink.Rule
}

func (m *mockRuleHandle) RuleList(family int) ([]netlink.Rule, error) {
	return m.ruleList, nil
}

func (*mockRuleHandle) NewRule() *netlink.Rule {
	return netlink.NewRule()
}

func (m *mockRuleHandle) RuleAdd(rule *netlink.Rule) error {
	m.addedRule = rule
	return nil
}

func TestEnsureRomanaRouteRule(t *testing.T) {
	cases := []struct {
		name     string
		tableId  int
		ruleList []netlink.Rule
		test     func(*netlink.Rule) bool
	}{
		{
			"append rule",
			10,
			[]netlink.Rule{
				netlink.Rule{Table: 0},
				netlink.Rule{Table: 400},
			},
			func(r *netlink.Rule) bool { return r.Table == 10 },
		},
		{
			"do not append rule",
			10,
			[]netlink.Rule{
				netlink.Rule{Table: 0},
				netlink.Rule{Table: 10},
			},
			func(r *netlink.Rule) bool { return r == nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mockRuleHandle{ruleList: tc.ruleList}
			err := EnsureRomanaRouteRule(tc.tableId, &m)
			if err != nil {
				t.Fatalf("failed to run EnsureRomanaRouteRule, err=%s", err)
			}
			if !tc.test(m.addedRule) {
				t.Fatalf("unexpected rule added %+v", m.addedRule)
			}
		})
	}

}
