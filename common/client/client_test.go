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
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
)

var (
	client *Client
)

type testLocker struct {
}

func (tl testLocker) Lock() {

}

func (tl testLocker) Unlock() {

}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func initClient(t *testing.T, topoConf string) *Client {
	cfg := &common.Config{EtcdEndpoints: []string{"localhost:2379"},
		EtcdPrefix: fmt.Sprintf("/romanaTest%d", rand.Int63n(100000)),
	}
	client, err = NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(topoConf), &topoReq)
	if err != nil {
		t.Fatalf("Cannot parse %s: %v", topoConf, err)
	}
	err = client.IPAM.UpdateTopology(topoReq)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func init() {
	testSaver = &TestSaver{}
}

func TestWatchHosts(t *testing.T) {
	topoConf := `{
  "networks":[
    {
      "name":"net1",
      "cidr":"10.0.0.0/30",
      "block_mask":30
    }
  ],
  "topologies":[
    {
      "networks":[
        "net1"
      ],
      "map":[
        {
          "routing":"foo",
          "groups":[{
            "name":"host1",
            "ip":"10.0.0.1"
          }]
        }
      ]
    }
  ]
}`
	stopMsg := new(struct{})
	client = initClient(t, topoConf)
	stopCh := make(chan struct{})
	ch, err := client.WatchHosts(stopCh)
	if err != nil {
		t.Fatal(err)
	}
	tryCount := 1
	maxTries := 5
	for {
		t.Logf("TestWatchHosts: Try %d\n", tryCount)
		select {
		case hosts := <-ch:
			t.Logf("TestWatchHosts: On try %d received %d hosts (rev %d)", tryCount, len(hosts.Hosts), hosts.Revision)
		default:
			if tryCount < maxTries-1 {
				hgs := client.IPAM.GetGroupsForNetwork("net1")
				newHostIP := fmt.Sprintf("10.0.0.%d", tryCount+1)
				newHostName := fmt.Sprintf("host%d", tryCount+1)
				err := hgs.AddHost(api.Host{IP: net.ParseIP(newHostIP),
					Name: newHostName,
				})
				if err != nil {
					t.Fatalf("TestWatchHosts: Error adding host %s: %s", newHostIP, err)
				}
				tryCount++
			} else {
				t.Logf("TestWatchHosts: Stopping the watcher after %d tries", maxTries)
				stopCh <- *stopMsg
				return
			}
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func TestWatchBlocks(t *testing.T) {
	topoConf := `{
  "networks":[
    {
      "name":"net1",
      "cidr":"10.0.0.0/30",
      "block_mask":31
    }
  ],
  "topologies":[
    {
      "networks":[
        "net1"
      ],
      "map":[
        {
          "routing":"foo",
          "groups":[{
            "name":"host1",
            "ip":"10.0.0.1"
          }]
        }
      ]
    }
  ]
}`
	stopMsg := new(struct{})
	client = initClient(t, topoConf)
	stopCh := make(chan struct{})
	ch, err := client.WatchBlocks(stopCh)
	if err != nil {
		t.Fatal(err)
	}
	tryCount := 1
	maxTries := 5
	for {
		t.Logf("TestWatchBlocks: Try %d\n", tryCount)
		select {
		case blocks := <-ch:
			t.Logf("TestWatchBlocks: On try %d received %d blocks (rev %d)", tryCount, len(blocks.Blocks), blocks.Revision)
		default:
			if tryCount < maxTries-1 {
				ip, err := client.IPAM.AllocateIP(fmt.Sprintf("Address%d", tryCount), "host1", "ten1", "seg1")
				if err != nil {
					t.Fatalf("TestWatchBlocks: Error allocating IP: %s", err)
				}
				t.Logf("TestWatchBlocks: Allocated IP %s", ip)
				tryCount++
			} else {
				t.Logf("TestWatchBlocks: Stopping the watcher after %d tries", maxTries)
				stopCh <- *stopMsg
				return
			}
		}
		time.Sleep(1 * time.Millisecond)
	}
}
