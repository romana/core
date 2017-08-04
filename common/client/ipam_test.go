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
	"net"
	"testing"

	"github.com/romana/core/common/api"
)

var (
	testSaver *TestSaver
	ipam      *IPAM
)

func initIpam(t *testing.T, conf string) *IPAM {
	// If not specified, load from file named after this test
	if conf == "" {
		testName := t.Name()
		fileName := fmt.Sprintf("testdata/%s.json", testName)
		t.Logf("Loading data for %s from %s", testName, fileName)
		b, err := ioutil.ReadFile(fileName)
		if err != nil {
			t.Fatal(err)
		}
		if err != nil {
			t.Fatal(err)
		}
		conf = string(b)
	}
	ipam, err := NewIPAM(testSaver.save, nil)
	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(conf), &topoReq)
	if err != nil {
		t.Fatalf("Cannot parse %s: %v", conf, err)
	}
	err = ipam.UpdateTopology(topoReq)
	if err != nil {
		t.Fatal(err)
	}
	return ipam
}

func init() {
	testSaver = &TestSaver{}
}

// TestSaver can be used as the Saver function for IPAM.
// It will store last saved data in lastJson field, which
// can be helpful for debugging.
type TestSaver struct {
	lastJson string
}

func (s *TestSaver) save(ipam *IPAM) error {
	b, err := json.MarshalIndent(ipam, "", "  ")
	if err != nil {
		return err
	}
	s.lastJson = string(b)

	return nil
}

func TestNewCIDR(t *testing.T) {
	cidr, err := NewCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	if cidr.StartIP.String() != "10.0.0.0" {
		t.Fatalf("Expected start to be 10.0.0.0, got %s", cidr.StartIP)
	}

	if cidr.EndIP.String() != "10.255.255.255" {
		t.Fatalf("Expected start to be 10.255.255.255 got %s", cidr.StartIP)
	}
}

func TestBlackout(t *testing.T) {
	ipam = initIpam(t, "")

	// 1. Black out something random
	err = ipam.BlackOut("10.100.100.100/24")
	if err == nil {
		t.Fatal("TestChunkBlackout: Expected error that no network found")
	}

	// 2. Black out 10.0.0.0/30 - should be an error
	err = ipam.BlackOut("10.0.0.0/30")
	if err == nil {
		t.Fatal("TestChunkBlackout: Expected error because cannot contain entire network")
	}
	t.Logf("TestChunkBlackout: Received expected error: %s", err)

	// 3. Black out 10.0.0.0/32
	err = ipam.BlackOut("10.0.0.0/32")
	if err != nil {
		t.Fatal(err)
	}

	// 4. Black out 10.0.0.0/31 -- it should silently succeed but,
	// will replace /32
	err = ipam.BlackOut("10.0.0.0/31")
	if err != nil {
		t.Fatal(err)
	}

	// 4. Allocate IP - should start with 10.0.0.2
	ip, err := ipam.AllocateIP("1", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlackout: 1. Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.2" {
		t.Fatalf("Expected 10.0.0.2, got %s", ip)
	}

	ip, err = ipam.AllocateIP("2", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlackout: 2. Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.3" {
		t.Fatalf("Expected 10.0.0.3, got %s", ip)
	}

	// Now this should fail.
	ip, err = ipam.AllocateIP("3", "host1", "ten1", "seg1")
	if err == nil {
		t.Fatalf("Expected an error, received an IP: %s", ip)
	}

	if err.Error() != msgNoAvailableIP {
		t.Fatalf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
	}

	// 6. Try to black out already allocated chunk, should get error.
	err = ipam.BlackOut("10.0.0.2/31")
	if err == nil {
		t.Fatalf("Expected error because trying to black out allocated IPs")
	} else {
		t.Logf("Received expected error: %s", err)
	}
	// 7. Remove blackout
	err = ipam.UnBlackOut("10.0.0.0/30")
	if err == nil {
		t.Fatalf("Expected error as no such CIDR to remove from blackout, got nothing")
	}
	t.Logf("Received expected error %s", err)

	err = ipam.UnBlackOut("10.0.0.0/31")
	if err != nil {
		t.Fatal(err)
	}
	// 8. Try allocating IPs again, will get them from the previously blacked out range.
	ip, err = ipam.AllocateIP("4", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlackout: 4. Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}
	ip, err = ipam.AllocateIP("5", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlackout: 5. Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.1" {
		t.Fatalf("Expected 10.0.0.1, got %s", ip)
	}

	// 9. Now this should fail -- network is full
	t.Logf("Next allocation should fail - network is full.")
	ip, err = ipam.AllocateIP("6", "host1", "ten1", "seg1")
	if err == nil {
		t.Fatalf("Expected an error, received an IP: %s", ip)
	}

	if err.Error() != msgNoAvailableIP {
		t.Fatalf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
	}
	t.Logf("TestChunkBlackout done.")
}

// TestIPReuse tests that an IP can be reused.
func TestIPReuse(t *testing.T) {
	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("1", "host1", "ten1", "seg1")
	t.Logf("TestChunkIPReuse: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}

	ip, err = ipam.AllocateIP("2", "host1", "ten1", "seg1")
	t.Logf("TestChunkIPReuse: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.1" {
		t.Fatalf("Expected 10.0.0.1, got %s", ip)
	}

	// Now this should fail.
	ip, err = ipam.AllocateIP("3", "host1", "ten1", "seg1")
	if err == nil {
		t.Fatalf("Expected an error, received an IP: %s", ip)
	}

	if err.Error() != msgNoAvailableIP {
		t.Fatalf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
	}

	// Deallocate first IP
	err = ipam.DeallocateIP("1")
	if err != nil {
		t.Fatal(err)
	}

	// This should succeed
	ip, err = ipam.AllocateIP("4", "host1", "ten1", "seg1")
	t.Logf("TestChunkIPReuse: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}
}

func TestBlockReuseMask32(t *testing.T) {
	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("1", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}

	ip, err = ipam.AllocateIP("2", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.1" {
		t.Fatalf("Expected 10.0.0.1, got %s", ip)
	}

	// Now this should fail.
	ip, err = ipam.AllocateIP("3", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
	if err == nil {
		t.Fatalf("Expected an error, received an IP: %s", ip)
	}

	if err.Error() != msgNoAvailableIP {
		t.Fatalf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
	}

	// Deallocate first IP
	err = ipam.DeallocateIP("1")
	if err != nil {
		t.Fatal(err)
	}

	// This should succeed
	ip, err = ipam.AllocateIP("4", "host1", "ten1", "seg1")
	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}
}

func TestBlockReuseMask30(t *testing.T) {
	ipam = initIpam(t, "")

	// 1. Allocate first 4 (/30) addresses
	for i := 0; i < 4; i++ {
		addr := fmt.Sprintf("addr%d", i)
		ip, err := ipam.AllocateIP(addr, "host1", "ten1", "seg1")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("TestBlockReuse: Allocated %s: %s for ten1:seg1", addr, ip)
		expectIP := fmt.Sprintf("10.0.0.%d", i)
		if ip.String() != expectIP {
			t.Fatalf("Expected %s, got %s", expectIP, ip)
		}
		blockCount := len(ipam.ListAllBlocks().Blocks)
		if blockCount != 1 {
			t.Fatalf("Expected block count to be 1, have %d", blockCount)
		}
	}

	// 2. Deallocate two addresses
	err := ipam.DeallocateIP("addr2")
	if err != nil {
		t.Log(testSaver.lastJson)
		t.Fatal(err)
	}
	t.Log("Deallocated addr2")

	err = ipam.DeallocateIP("addr3")
	if err != nil {
		t.Log(testSaver.lastJson)
		t.Fatal(err)
	}
	t.Log("Deallocated addr3")

	// 3. Allocate two addresses again. We should get them within first block.
	ip, err := ipam.AllocateIP("addr2.1", "host1", "ten1", "seg1")
	if err != nil {
		t.Fatal(err)
	}
	expectIP := "10.0.0.2"
	if ip.String() != expectIP {
		t.Fatalf("Expected %s, got %s", expectIP, ip)
	}
	t.Logf("TestBlockReuse: Allocated addr2.1: %s for ten1:seg1", ip)

	ip, err = ipam.AllocateIP("addr3.1", "host1", "ten1", "seg1")
	if err != nil {
		t.Fatal(err)
	}
	expectIP = "10.0.0.3"
	if ip.String() != expectIP {
		t.Fatalf("Expected %s, got %s", expectIP, ip)
	}
	t.Logf("TestBlockReuse: Allocated addr 3.1: %s for ten1:seg1", ip)

	blockCount := len(ipam.ListAllBlocks().Blocks)
	if blockCount != 1 {
		t.Fatalf("Expected block count to be 1, have %d", blockCount)
	}

	// 4. Allocate another 4 addresses. We should now have 2 blocks.
	for i := 4; i < 8; i++ {
		addr := fmt.Sprintf("addr%d", i)
		ip, err := ipam.AllocateIP(addr, "host1", "ten1", "seg1")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("TestBlockReuse: Allocated %s for ten1:seg1", ip)
		expectIP := fmt.Sprintf("10.0.0.%d", i)
		if ip.String() != expectIP {
			t.Fatalf("Expected %s, got %s", expectIP, ip)
		}
		blockCount := len(ipam.ListAllBlocks().Blocks)
		if blockCount != 2 {
			t.Fatalf("Expected block count to be 2, have %d", blockCount)
		}
	}

	// 5. Delete first 4 addresses.
	for _, addr := range []string{"addr0", "addr1", "addr2.1", "addr3.1"} {
		err := ipam.DeallocateIP(addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Deallocated %s", addr)
	}
	// We should now have 2 blocks still - but one is reusable
	blockCount = len(ipam.ListAllBlocks().Blocks)
	if blockCount != 2 {
		t.Fatalf("Expected block count to be 2, have %d", blockCount)
	}
	for i, block := range ipam.ListAllBlocks().Blocks {
		t.Logf("Block %d has %d allocated addresses", i, block.AllocatedIPCount)
		if i == 0 && block.AllocatedIPCount != 0 {
			t.Fatalf("Expected block 0 to have 0 IPs allocated, got %d", block.AllocatedIPCount)
		}
	}

	// 6. Allocate two addresses, we should now have 2 blocks - starting with 10.0.0.0
	// And 0 block should have 2 IP
	ip, err = ipam.AllocateIP("addr0.1", "host1", "ten1", "seg1")
	if err != nil {
		t.Fatal(err)
	}
	expectIP = "10.0.0.0"
	if ip.String() != expectIP {
		t.Fatalf("Expected %s, got %s", expectIP, ip)
	}
	t.Logf("TestBlockReuse: Allocated %s for ten1:seg1", ip)

	ip, err = ipam.AllocateIP("addr0.2", "host1", "ten1", "seg1")
	if err != nil {
		t.Fatal(err)
	}
	expectIP = "10.0.0.1"
	if ip.String() != expectIP {
		t.Fatalf("Expected %s, got %s", expectIP, ip)
	}
	t.Logf("TestBlockReuse: Allocated %s for ten1:seg1", ip)

	blockCount = len(ipam.ListAllBlocks().Blocks)
	if blockCount != 2 {
		t.Fatalf("Expected block count to be 2, have %d", blockCount)
	}

	for i, block := range ipam.ListAllBlocks().Blocks {
		t.Logf("Block %d has %d allocated addresses", i, block.AllocatedIPCount)
		if i == 0 && block.AllocatedIPCount != 2 {
			t.Fatalf("Expected block 0 to have 0 IPs allocated, got %d", block.AllocatedIPCount)
		}
	}

	t.Log("All good for TestBlockReuseMask30")
}

// Test32 tests bitmask size 32 - as a corner case.
func Test32_1(t *testing.T) {
	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("1", "host1", "ten1", "seg1")
	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}

	ip, err = ipam.AllocateIP("2", "host1", "ten1", "seg1")
	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.1" {
		t.Fatalf("Expected 10.0.0.1, got %s", ip)
	}

}

func Test32_2(t *testing.T) {

	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("2", "host1", "ten1", "seg1")
	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}

	// Now this should fail - only one /32 block can be there on a /32 net.
	ip, err = ipam.AllocateIP("3", "host1", "ten1", "seg1")
	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
	if err == nil {
		t.Fatalf("Expected an error, received an IP: %s", ip)
	}

	if err.Error() != msgNoAvailableIP {
		t.Fatalf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
	}
}

// TestSegments tests that segments get different blocks.
func TestSegments(t *testing.T) {
	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("x1", "host1", "ten1", "seg1")
	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}

	ip, err = ipam.AllocateIP("x2", "host1", "ten1", "seg1")
	t.Logf("TestSegments: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.1" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip)
	}

	// This should go into a separate chunk
	ip, err = ipam.AllocateIP("x3", "host1", "ten1", "seg2")
	t.Logf("TestChunkSegments: Allocated %s for ten1:seg2", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.4" {
		t.Fatalf("Expected 10.0.0.4, got %s", ip)
	}
}

// TestTenants tests that addresses are allocated from networks
// on which provided tenants are allowed.
func TestTenants(t *testing.T) {
	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("x1", "host1", "tenant1", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.200.0.0" {
		t.Fatalf("Expected 10.200.0.0, got %s", ip.String())
	}

	ip, err = ipam.AllocateIP("x2", "host1", "tenant2", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.200.0.8" {
		t.Fatalf("Expected 10.200.0.8, got %s", ip.String())
	}

	ip, err = ipam.AllocateIP("x3", "host1", "tenant3", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.220.0.0" {
		t.Fatalf("Expected 10.220.0.0, got %s", ip.String())
	}

	// This one should get allocate from net3 - wildcard network
	ip, err = ipam.AllocateIP("x4", "host1", "someothertenant", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.240.0.0" {
		t.Fatalf("Expected 10.240.0.0, got %s", ip.String())
	}

	// TODO allocate no host
	ip, err = ipam.AllocateIP("x5", "no.such.host", "someothertenant", "")
	if err == nil {
		t.Fatalf("Expected an error")
	}
	if ip != nil {
		t.Fatalf("Expected a nil ip, got %v", ip)
	}
	t.Logf("Got %s", err)
}

func TestHostAllocation(t *testing.T) {
	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("x1", "ip-192-168-99-10", "tenant1", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip.String())
	}

	ip, err = ipam.AllocateIP("x2", "ip-192-168-99-11", "tenant1", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.4" {
		t.Fatalf("Expected 10.0.0.4, got %s", ip.String())
	}
	t.Logf("Saved state: %s", testSaver.lastJson)
}

func TestJsonParsing(t *testing.T) {
	var conf string

	// Slide 12: Example 1: Simple, flat network
	t.Log("Example 1: Simple, flat network, (a)")
	conf = `{
  "networks":[
    {
      "name":"vlanA",
      "cidr":"10.1.0.0/16",
      "block_mask": 28
    }
  ],
  "topologies":[
    {
      "networks":[
        "vlanA"
      ],
      "map":[
        {
          "routing":"block-on-host",
          "groups":[
            { "name" : "h1", "ip" : "1.1.1.1" },
            { "name" : "h1", "ip" : "1.1.1.1" },
            { "name" : "h1", "ip" : "1.1.1.1" },
            { "name" : "h1", "ip" : "1.1.1.1" }
          ]
        }
      ]
    }
  ]
}`
	initIpam(t, conf)
	t.Logf("Slide 12: Example 1: Simple, flat network JSON:\n%s\n", testSaver.lastJson)

	// Slide 13: Example 1: Simple, flat network
	t.Logf("Example 1: Simple, flat network, (b)")
	conf = `{
  "networks":[
    {
      "name":"vlanA",
      "cidr":"10.1.0.0/16",
      "block_mask": 28
   
    }
  ],
  "topologies":[
    {
      "networks":[
        "vlanA"
      ],
      "map":[
        {
          "routing":"block-announce-bgp:peerxxxxx",
          "groups":[
            { "name" : "h1", "ip" : "1.1.1.1" },
            { "name" : "h2", "ip" : "1.1.1.1" },
            { "name" : "h3", "ip" : "1.1.1.1" },
            { "name" : "h4", "ip" : "1.1.1.1" }
          ]
        }
      ]
    }
  ]
}`
	initIpam(t, conf)
	t.Logf("Slide 13: Example 1: Simple, flat network:\n%s\n", testSaver.lastJson)

	// Slide 14: Example 1: Simple, flat network
	t.Logf("Example 1: Simple, flat network, (c)")
	conf = `{
  "networks":[
    {
      "name":"vlanA",
      "cidr":"10.1.0.0/16",
      "block_mask" : 28
    }
  ],
  "topologies":[
    {
      "networks":[
        "vlanA"
      ],
      "map":[
        {
          "routing":"block-on-host,block - announce - bgp: peerxxxxx",
          "groups":[
            { "name" : "h1", "ip" : "1.1.1.1" },
            { "name" : "h1", "ip" : "1.1.1.1" },
            { "name" : "h1", "ip" : "1.1.1.1" },
            { "name" : "h1", "ip" : "1.1.1.1" }
          ]
        }
      ]
    }
  ]
}`
	initIpam(t, conf)
	t.Logf("Slide 14: Example 1: Simple, flat network JSON:\n%s\n", testSaver.lastJson)

	// Slide 15: Example 2: Prefix per host
	t.Logf("Example 2: Prefix per host (a)")
	conf = `{
  "networks":[
    {
      "name":"vlanA",
      "cidr":"10.1.0.0/16",
      "block_mask" : 28
    }
  ],
  "topologies":[
    {
      "networks":[
        "vlanA"
      ],
      "map":[
        {
          "routing":"prefix-on-host",
          "groups":[
            { "name" : "h1", "ip" : "1.1.1.1" }
          ]
        },
        {
          "routing":"prefix-on-host",
          "groups":[
            { "name" : "h1", "ip" : "1.1.1.1" }
          ]
        },
        {
          "routing":"prefix-on-host",
          "groups":[ { "name" : "h1", "ip" : "1.1.1.1" } ]
        },
        {
          "routing":"prefix-on-host",
          "groups":[ { "name" : "h1", "ip" : "1.1.1.1" } ]
        }
      ]
    }
  ]
}`
	initIpam(t, conf)
	t.Logf("Slide 15: Example 2: Prefix per host JSON:\n%s\n", testSaver.lastJson)

	// Slide 16: Example 2: Prefix per host
	t.Logf("Example 2: Prefix per host (b)")
	conf = `{
  "networks":[
    {
      "name":"vlanA",
      "cidr":"10.1.0.0/16",
      "block_mask" : 28
    }
  ],
  "topologies":[
    {
      "networks":[
        "vlanA"
      ],
      "map":[
            {
              "routing":"prefix-announce-bgp:peerxxxx",
              "groups":[ { "name" : "h1", "ip" : "1.1.1.1" } ]
            },
            {
              "routing":"prefix-announce-bgp:peerxxxx",
              "groups":[ { "name" : "h1", "ip" : "1.1.1.1" } ]
            },
            {
              "routing":"prefix-announce-bgp:peerxxxx",
              "groups":[ { "name" : "h1", "ip" : "1.1.1.1" } ]
            },
            {
              "routing":"prefix-announce-bgp:peerxxxx",
              "groups":[ { "name" : "h1", "ip" : "1.1.1.1" }  ]
            }
      ]
    }
  ]
}`
	initIpam(t, conf)
	t.Logf("Slide 16: Example 2: Prefix per host JSON:\n%s\n", testSaver.lastJson)

	// Slide 17: Example 3: Multi-host groups + prefix
	t.Logf("Example 3: Multi-host groups + prefix")
	conf = `{
  "networks":[
    {
      "name":"vlanA",
      "cidr":"10.1.0.0/16",
      "block_mask" : 28
    }
  ],
  "topologies":[
    {
      "networks":[
        "vlanA"
      ],
      "map":[
        {
          "routing":"block-host-routes, prefix-announce-bgp:peerxxxx",
          "groups":[ { "name" : "h1", "ip" : "1.1.1.1" }, { "name" : "h1", "ip" : "1.1.1.1" } ]
        },
        {
          "routing":"block-host-routes, prefix-announce-bgp:peerxxxx",
          "groups":[ { "name" : "h1", "ip" : "1.1.1.1" }, { "name" : "h1", "ip" : "1.1.1.1" } ]
        },
        {
          "routing":"block-host-routes, prefix-announce-bgp:peerxxxx",
          "groups":[ { "name" : "h1", "ip" : "1.1.1.1" }, { "name" : "h1", "ip" : "1.1.1.1" } ]
        },
        {
          "routing":"block-host-routes, prefix-announce-bgp:peerxxxx",
          "groups":[ { "name" : "h1", "ip" : "1.1.1.1" }, { "name" : "h1", "ip" : "1.1.1.1" } ]
        }
      ]
    }
  ]
}`
	initIpam(t, conf)
	t.Logf("Slide 17: Example 3: Multi-host groups + prefix JSON:\n%s\n", testSaver.lastJson)

	// Slide 18: Example 4: VPC routing for two AZs
	t.Logf("Example 4: VPC routing for two AZs")
	conf = `{
  "networks":[
    {
      "name":"subnetA",
      "cidr":"10.1.0.0/16",
      "block_mask" : 28
    },
    {
      "name":"subnetB",
      "cidr":"10.2.0.0/16",
      "block_mask" : 28
    }
  ],
  "topologies":[
    {
      "networks":[
        "subnetA"
      ],
      "map":[
        {
          "routing":"block-host-routes,prefix-announce-vpc",
          "groups":[]
        },
        {
          "routing":"block-host-routes,prefix-announce-vpc",
          "groups":[]
        }
      ]
    },
    {
      "networks":[
        "subnetB"
      ],
      "map":[
        {
          "routing":"block-host-routes,prefix-announce-vpc",
          "groups":[]
        },
        {
          "routing":"block-host-routes,prefix-announce-vpc",
          "groups":[]
        }
      ]
    }
  ]
}`
	initIpam(t, conf)
	t.Logf("Slide 18: Example 4: VPC routing for two AZs JSON:\n%s\n", testSaver.lastJson)

}

// TestOutOfBoundsError tests an error happening in tests for romana 2.0
func TestOutOfBoundsError(t *testing.T) {
	ipam = initIpam(t, "")
	maxAddrCnt := 6
	for i := 0; i < maxAddrCnt; i++ {
		addr := fmt.Sprintf("addr%d", i)
		ip, err := ipam.AllocateIP(addr, "host1", "ten1", "seg1")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("TestBlockReuse: Allocated %s for ten1:seg1", ip)
		expectIP := fmt.Sprintf("10.0.0.%d", i)
		if ip.String() != expectIP {
			t.Fatalf("Expected %s, got %s", expectIP, ip)
		}

	}
	t.Logf("Allocated %d addresses", maxAddrCnt)
	for i, block := range ipam.ListAllBlocks().Blocks {
		t.Logf("Block %d has %d allocated addresses", i, block.AllocatedIPCount)
	}

	for i := 0; i < maxAddrCnt; i++ {
		addr := fmt.Sprintf("addr%d", i)
		err := ipam.DeallocateIP(addr)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("Dellocated %d addresses", maxAddrCnt)
	for i, block := range ipam.ListAllBlocks().Blocks {
		t.Logf("Block %d has %d allocated addresses", i, block.AllocatedIPCount)
	}
}

//func TestGenerateJSONSimple(t *testing.T) {
//	updateReq := api.TopologyUpdateRequest{}
//	net1 := api.NetworkDefinition{BlockMask: 30,
//		CIDR: "10.0.0.0/16",
//		Name: "net1",
//	}
//	updateReq.Networks = []api.NetworkDefinition{net1}
//	group1 := api.GroupOrHost{Name: "group1",
//		Groups: make([]api.GroupOrHost, 0),
//	}
//	group2 := api.GroupOrHost{Name: "group2",
//		Groups: make([]api.GroupOrHost, 0),
//	}
//	topoDef1 := api.TopologyDefinition{Networks: []string{"net1"},
//		Map: []api.GroupOrHost{group1, group2},
//	}
//	updateReq.Topologies = []api.TopologyDefinition{topoDef1}
//	b, err := json.Marshal(updateReq)
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Logf(string(b))
//}

func TestHostAdditionSimple(t *testing.T) {

	t.Logf("TestHostAdditionSimple")

	ipam = initIpam(t, "")
	//	t.Logf(testSaver.lastJson)

	for i := 0; i < 4; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.10.10.1%d", i))
		name := fmt.Sprintf("host%d", i)
		host := api.Host{Name: name,
			IP: ip,
		}
		err := ipam.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
	}
	// We should have 2 hosts in each group now.
	net1 := ipam.Networks["net1"]
	for _, grp := range net1.Group.Groups {
		if len(grp.Hosts) != 2 {
			t.Fatalf("Expected group %s to have 2 hosts, it has %d", grp.Name, len(grp.Hosts))
		}
		t.Logf("Hosts in group %s: %v", grp.Name, grp.Hosts)
	}

	// 	t.Logf(testSaver.lastJson)

}
