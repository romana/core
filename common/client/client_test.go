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
	"sort"
	"testing"

	"github.com/romana/core/common/api"
)

/*
var (
	client *Client
	// Keep track of state of some tests
	state int
)

func init() {
	rand.Seed(time.Now().UnixNano())
	testSaver = &TestSaver{}
}

func tearDown(t *testing.T) {
	var err error
	err = client.Store.DeleteTree(client.config.EtcdPrefix)
	if err != nil {
		t.Errorf("Error tearing down: %s", err)
	}
	t.Logf("Tore down %s", client.config.EtcdPrefix)
}

func initClient(t *testing.T, topoConf string) *Client {
	var err error
	cfg := &common.Config{EtcdEndpoints: []string{"localhost:2379"},
		EtcdPrefix: fmt.Sprintf("/romanaTest%d", rand.Int63n(100000)),
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if topoConf != "" {
		topoReq := api.TopologyUpdateRequest{}
		err = json.Unmarshal([]byte(topoConf), &topoReq)
		if err != nil {
			t.Fatalf("Cannot parse %s: %v", topoConf, err)
		}
		err = client.IPAM.UpdateTopology(topoReq, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	return client
}
*/

// TestWatchHostsWithCallback tests WatchHostsWithCallback -- and since it
// uses WatchHosts internally, implicitly also WatchHosts
/*
func TestWatchHostsWithCallback(t *testing.T) {
	client := initClient(t, "")
	defer tearDown(t)
	errCh := make(chan string)
	okCh := make(chan string)
	err := client.WatchHostsWithCallback(func(hl api.HostList) {
		state++

		var msg string
		fmt.Printf("HostListCallback: Got host list of length %d and revision %d in state %d\n", len(hl.Hosts), hl.Revision, state)
		if state == 1 {
			if len(hl.Hosts) != 0 {
				msg = fmt.Sprintf("HostListCallback: Expected host length at this point to be 0, got %d", len(hl.Hosts))
				fmt.Println(msg)
				errCh <- msg
				return
			}
			if hl.Revision != 0 {
				msg = fmt.Sprintf("HostListCallback: Expected host list revision at this point to be 0, got %d", hl.Revision)
				fmt.Println(msg)
				errCh <- msg
				return
			}
		} else if state == 2 {
			if len(hl.Hosts) != 2 {
				msg = fmt.Sprintf("HostListCallback: Expected host length at this point to be 2, got %d", len(hl.Hosts))
				fmt.Println(msg)
				errCh <- msg
				return
			}
			if hl.Revision != 1 {
				msg = fmt.Sprintf("HostListCallback: Expected host list revision at this point to be 1, got %d", hl.Revision)
				fmt.Println(msg)
				errCh <- msg
				return
			}
			// Here everything is ok!
			okCh <- "OK"
		} else {
			msg = fmt.Sprintf("HostListCallback: Did not expect HostListCallback to be called in state %d", state)
			fmt.Println(state)
			errCh <- msg

		}

	})
	if err != nil {
		t.Fatal(err)
	}

	topoConf := `{
	"networks": [{
		"name": "net1",
		"cidr": "10.0.0.0/8",
		"block_mask": 30
	}],

	"topologies": [{
		"networks": ["net1"],
		"map": [{
			"routing": "bla",
			"groups": [{
					"name": "host1",
					"ip": "192.168.99.10"
				},
				{
					"name": "host2",
					"ip": "192.168.99.11"
				}
			]
		}]
	}]
}`
	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(topoConf), &topoReq)
	if err != nil {
		t.Fatalf("Cannot parse %s: %v", topoConf, err)
	}
	err = client.IPAM.UpdateTopology(topoReq)
	if err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case msg := <-errCh:
			t.Fatal(msg)
			break
		case <-okCh:
			return
		}
	}

}
*/

// TestWatchBlocksWithCallback tests WatchBlocksWithCallback -- and since it
// uses WatchBlocks internally, implicitly also WatchBlocks
/*
func TestWatchBlocksWithCallback(t *testing.T) {
	defer tearDown(t)
	errCh := make(chan string)
	okCh := make(chan string)
	topoConf := `{
	"networks": [{
		"name": "net1",
		"cidr": "10.0.0.0/8",
		"block_mask": 31
	}],

	"topologies": [{
		"networks": ["net1"],
		"map": [{
			"routing": "bla",
			"groups": [{
					"name": "host1",
					"ip": "192.168.99.10"
				},
				{
					"name": "host2",
					"ip": "192.168.99.11"
				}
			]
		}]
	}]
}`
	client = initClient(t, topoConf)
	err := client.WatchBlocksWithCallback(func(hl api.IPAMBlocksResponse) {
		state++

		var msg string
		fmt.Printf("BlocksListCallback: Got block list of length %d and revision %d in state %d\n", len(hl.Blocks), hl.Revision, state)
		switch state {
		case 1:
			if len(hl.Blocks) != 0 {
				msg = fmt.Sprintf("BlocksListCallback: Expected block length at this point to be 0, got %d", len(hl.Blocks))
				fmt.Println(msg)
				errCh <- msg
				return
			}
			if hl.Revision != 0 {
				msg = fmt.Sprintf("BlocksListCallback: Expected block list revision at this point to be 0, got %d", hl.Revision)
				fmt.Println(msg)
				errCh <- msg
				return
			}
		case 2, 3:
			if len(hl.Blocks) != 1 {
				msg = fmt.Sprintf("BlocksListCallback: Expected block length at this point to be 1, got %d", len(hl.Blocks))
				fmt.Println(msg)
				errCh <- msg
				return
			}
			if hl.Revision != state-1 {
				msg = fmt.Sprintf("HostListCallback: Expected block list revision at this point to be %d, got %d", state-1, hl.Revision)
				fmt.Println(msg)
				errCh <- msg
				return
			}

		case 4, 5:
			if len(hl.Blocks) != 2 {
				msg = fmt.Sprintf("BlocksListCallback: Expected block length at this point to be 2, got %d", len(hl.Blocks))
				fmt.Println(msg)
				errCh <- msg
				return
			}
			if hl.Revision != state-1 {
				msg = fmt.Sprintf("HostListCallback: Expected block list revision at this point to be %d, got %d", state-1, hl.Revision)
				fmt.Println(msg)
				errCh <- msg
				return
			}
			if state == 5 {
				// Here everything is ok!
				okCh <- "OK"
			}
		default:
			msg = fmt.Sprintf("HostListCallback: Did not expect HostListCallback to be called in state %d", state)
			errCh <- msg

		}

	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.IPAM.AllocateIP("addr1", "host1", "t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.IPAM.AllocateIP("addr2", "host1", "t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.IPAM.AllocateIP("addr3", "host1", "t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.IPAM.AllocateIP("addr4", "host1", "t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case msg := <-errCh:
			t.Fatal(msg)
			break
		case <-okCh:
			return
		}
	}
}
*/

/*
func TestConcurrency(t *testing.T) {
	//	defer tearDown(t)
	client = initClient(t, "")

	barrier := make(chan int)
	cnt := 8
	locker, err := client.Store.NewLocker("/lock")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cnt; i++ {
		go func(i int) {
			fmt.Printf("%d %d Entered\n", i, getGID())
			defer func(i int) {
				fmt.Printf("%d %d Unlocking\n", i, getGID())
				locker.Unlock()
				fmt.Printf("%d %d Unlocked\n", i, getGID())
			}(i)
			fmt.Printf("%d %d Waiting for lock\n", i, getGID())
			locker.Lock()
			fmt.Printf("%d %d Got lock\n", i, getGID())
			val := fmt.Sprintf("Hello from %d %d", i, getGID())
			err := client.Store.Put(fmt.Sprintf("/test%d", i), []byte(val), nil)
			if err != nil {
				fmt.Println(err)
			}
			barrier <- 1
		}(i)
	}
	finishedCnt := 0

WAIT_FOR_FINISH:
	for {
		select {
		case <-barrier:
			finishedCnt++
			fmt.Printf("%d routines finished\n", finishedCnt)
			if finishedCnt == cnt {
				break WAIT_FOR_FINISH
			}
		}
	}
}
*/

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
			got := getTopologyFromIPAMState(tt.ipam)
			gotTUR, ok := got.(*api.TopologyUpdateRequest)
			if !ok {
				t.Fatalf("error while fetching topology from IPAM: %v", got)
			}
			sortNetworks := func(i, j int) bool {
				return gotTUR.Networks[i].Name < gotTUR.Networks[j].Name
			}
			sortTopologies := func(i, j int) bool {
				return gotTUR.Topologies[i].Networks[0] < gotTUR.Topologies[j].Networks[0]
			}
			sort.SliceStable(gotTUR.Networks, sortNetworks)
			sort.SliceStable(gotTUR.Topologies, sortTopologies)

			wantTUR, ok := tt.want.(*api.TopologyUpdateRequest)
			if !ok {
				t.Fatalf("error while processing IPAM state: %v", tt.want)
			}
			sortNetworks = func(i, j int) bool {
				return wantTUR.Networks[i].Name < wantTUR.Networks[j].Name
			}
			sortTopologies = func(i, j int) bool {
				return wantTUR.Topologies[i].Networks[0] < wantTUR.Topologies[j].Networks[0]
			}
			sort.SliceStable(wantTUR.Networks, sortNetworks)
			sort.SliceStable(wantTUR.Topologies, sortTopologies)

			if !reflect.DeepEqual(gotTUR, wantTUR) {
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
