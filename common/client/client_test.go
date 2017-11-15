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

package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/romana/core/common/api"
)

type testcase struct {
	name string
	ipam *IPAM
	want interface{}
}

func loadTestFiles(name string, inFile string, outFile string) (testcase, error) {
	input, err := ioutil.ReadFile(inFile)
	if err != nil {
		return testcase{}, fmt.Errorf("error reading test input file: %s", err)
	}
	output, err := ioutil.ReadFile(outFile)
	if err != nil {
		return testcase{}, fmt.Errorf("error reading test output file: %s", err)
	}

	ipamState := &IPAM{}
	err = json.Unmarshal(input, ipamState)
	if err != nil {
		return testcase{}, fmt.Errorf("failed to unmarshal ipam information: %s", err)
	}
	topologyState := &api.TopologyUpdateRequest{}
	err = json.Unmarshal(output, topologyState)
	if err != nil {
		return testcase{}, fmt.Errorf("failed to unmarshal topology information: %s", err)
	}

	return testcase{name, ipamState, topologyState}, nil
}

func Test_getTopologyFromIPAMState(t *testing.T) {
	var testcases []testcase

	testfiles := map[string][]string{
		"multinetwork": {
			"testdata/TestTopologyGetInputMultiNetworks.json",
			"testdata/TestTopologyGetOutputMultiNetworks.json",
		},
		"kubeadm": {
			"testdata/TestTopologyGetInputKubeadm.json",
			"testdata/TestTopologyGetOutputKubeadm.json",
		},
	}

	for name, file := range testfiles {
		tc, err := loadTestFiles(name, file[0], file[1])
		if err != nil {
			t.Errorf("error loading test files: %s", err)
			continue
		}
		testcases = append(testcases, tc)
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			if got := getTopologyFromIPAMState(tt.ipam); !reflect.DeepEqual(got, tt.want) {
				bodyGot, errGot := json.MarshalIndent(got, "", "\t")
				bodyWant, errWant := json.MarshalIndent(tt.want, "", "\t")
				if errGot == nil && errWant == nil {
					t.Errorf("getTopology() = \ngot(%s)\nwant(%s)",
						string(bodyGot), string(bodyWant))
				} else {
					t.Errorf("getTopology() = \ngot(%#v)\nwant(%#v)", got, tt.want)
				}
			}
		})
	}
}
