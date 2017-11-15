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
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/romana/core/common/api"
)

func Test_getTopologyFromIPAMState(t *testing.T) {
	type args struct {
		ipamState *IPAM
	}

	input, err := ioutil.ReadFile("testdata/TestTopologyGetInputMultiNetworks.json")
	if err != nil {
		t.Fatalf("getTopology(): error reading test input file: %s", err)
	}
	output, err := ioutil.ReadFile("testdata/TestTopologyGetOutputMultiNetworks.json")
	if err != nil {
		t.Fatalf("getTopology(): error reading test output file: %s", err)
	}

	ipamState := &IPAM{}
	err = json.Unmarshal(input, ipamState)
	if err != nil {
		t.Fatalf("failed to unmarshal ipam information: %s", err)
	}
	topologyState := &api.TopologyUpdateRequest{}
	err = json.Unmarshal(output, topologyState)
	if err != nil {
		t.Fatalf("failed to unmarshal topology information: %s", err)
	}

	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			"TopologyMultiNetwork",
			args{ipamState},
			topologyState,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getTopologyFromIPAMState(tt.args.ipamState); !reflect.DeepEqual(got, tt.want) {
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
