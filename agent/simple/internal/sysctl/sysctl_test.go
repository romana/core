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

package sysctl

import (
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
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

func TestCheck(t *testing.T) {
	cases := []struct {
		name, path        string
		expect, expectErr bool
	}{
		{"check positive", "sysctl.golden", true, false},
		{"check negative", "sysctl.zero", false, false},
		{"check fail", "none", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Check(filepath.Join(testFileDir, tc.path))
			if err != nil && tc.expectErr == false {
				t.Errorf("Received unexpected error %s", err)
			}

			if ok != tc.expect {
				t.Errorf("Unexpected return value, expected %t, got %t", tc.expect, ok)
			}
		})
	}
}

func TestSet(t *testing.T) {
	err := Set("/tmp/doesnotexist")
	if err == nil {
		t.Fatalf("didn't fail when expected")
	}

	if _, ok := err.(errorSetBoundary); !ok {
		t.Fatalf("received unexpected error type %s.(%T)", err, err)
	}
}
