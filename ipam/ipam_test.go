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

package ipam

import (
	"encoding/json"
	"testing"

	"github.com/romana/core/pkg/api"
)

var (
	testSaver *TestSaver
)

func init() {
	testSaver = &TestSaver{}
}

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
		t.Error(err)
	}

	if cidr.StartIP.String() != "10.0.0.0" {
		t.Errorf("Expected start to be 10.0.0.0, got %s", cidr.StartIP)
	}

	if cidr.EndIP.String() != "10.255.255.255" {
		t.Errorf("Expected start to be 10.255.255.255 got %s", cidr.StartIP)
	}
}

//func TestChunkBlackout(t *testing.T) {
//	cidr1, err := NewCIDR("10.0.0.0/30")
//	if err != nil {
//		t.Error(err)
//	}
//
//	network1 := Network{CIDR: cidr1,
//		BlockMask: 30,
//	}
//
//	networks := []Network{network1}
//	ipam, err := NewIPAM(testSaver.save, nil)
//	if err != nil {
//		t.Error(err)
//	}
//
//	// 1. Black out something random
//	err = ipam.BlackOut("10.100.100.100/24")
//	if err == nil {
//		t.Errorf("Expected error that no network found")
//	}
//
//	// 2. Black out 10.0.0.0/30 - should be an error
//	err = ipam.BlackOut("10.0.0.0/30")
//	if err == nil {
//		t.Error("Expected error because cannot contain entire network")
//	}
//	t.Logf("Received expected error: %s", err)
//
//	// 3. Black out 10.0.0.0/32
//	err = ipam.BlackOut("10.0.0.0/32")
//	if err != nil {
//		t.Error(err)
//	}
//
//	// 4. Black out 10.0.0.0/31 -- it should silently succeed but,
//	// will replace /32
//	err = ipam.BlackOut("10.0.0.0/31")
//	if err != nil {
//		t.Error(err)
//	}
//
//	// 4. Allocate IP - should start with 10.0.0.2
//	ip, err := ipam.AllocateIP("bla", "host1", "ten1", "seg1")
//	t.Logf("TestChunkBlackout: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.2" {
//		t.Errorf("Expected 10.0.0.2, got %s", ip)
//	}
//
//	ip, err = ipam.AllocateIP("bla", "host1", "ten1", "seg1")
//	t.Logf("TestChunkBlackout: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.3" {
//		t.Errorf("Expected 10.0.0.3, got %s", ip)
//	}
//
//	// Now this should fail.
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlackout: Allocated %s for ten1:seg1", ip)
//	if err == nil {
//		t.Errorf("Expected an error, received an IP: %s", ip)
//	}
//
//	if err.Error() != msgNoAvailableIP {
//		t.Errorf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
//	}
//
//	// 6. Try to black out already allocated chunk, should get error.
//	err = ipam.BlackOut("10.0.0.2/31")
//	if err == nil {
//		t.Error("Expected error because trying to black out allocated IPs")
//	}
//	t.Logf("Received expected error: %s", err)
//
//	// 7. Remove blackout
//	err = ipam.UnBlackOut("10.0.0.0/30")
//	if err == nil {
//		t.Error("Expected error as no such CIDR to remove from blackout, got nothing")
//	}
//	t.Logf("Received expected error %s", err)
//
//	err = ipam.UnBlackOut("10.0.0.0/31")
//	if err != nil {
//		t.Error(err)
//	}
//	// 8. Try allocating IPs again, will get them from the previously blacked out range.
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlackout: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlackout: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.1" {
//		t.Errorf("Expected 10.0.0.1, got %s", ip)
//	}
//
//	// 9. Now this should fail -- network is full
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlackout: Allocated %s for ten1:seg1", ip)
//	if err == nil {
//		t.Errorf("Expected an error, received an IP: %s", ip)
//	}
//
//	if err.Error() != msgNoAvailableIP {
//		t.Errorf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
//	}
//}
//
//// TestChunkIPReuse tests that an IP can be reused.
//func TestChunkIPReuse(t *testing.T) {
//	cidr1, err := NewCIDR("10.0.0.0/31")
//	if err != nil {
//		t.Error(err)
//	}
//	network1 := Network{CIDR: cidr1,
//		BlockMask:      31,
//		AllowedTenants: []string{"*"},
//	}
//
//	networks := []Network{network1}
//	ipam, err := NewChunkIPAM(networks, testSaver.save, nil)
//	if err != nil {
//		t.Error(err)
//	}
//
//	ip, err := ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkIPReuse: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkIPReuse: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.1" {
//		t.Errorf("Expected 10.0.0.1, got %s", ip)
//	}
//
//	// Now this should fail.
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkIPReuse: Allocated %s for ten1:seg1", ip)
//	if err == nil {
//		t.Errorf("Expected an error, received an IP: %s", ip)
//	}
//
//	if err.Error() != msgNoAvailableIP {
//		t.Errorf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
//	}
//
//	// Deallocate first IP
//	err = ipam.DeallocateIP("10.0.0.0")
//	if err != nil {
//		t.Error(err)
//	}
//
//	// This should succeed
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkIPReuse: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//}
//
//// TestChunkBlockReuse tests that a block can be reused.
//func TestChunkBlockReuse(t *testing.T) {
//	cidr1, err := NewCIDR("10.0.0.0/31")
//	if err != nil {
//		t.Error(err)
//	}
//	network1 := Network{CIDR: cidr1,
//		BlockMask:      32,
//		AllowedTenants: []string{"*"},
//	}
//
//	networks := []Network{network1}
//	ipam, err := NewChunkIPAM(networks, testSaver.save, nil)
//	if err != nil {
//		t.Error(err)
//	}
//
//	ip, err := ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.1" {
//		t.Errorf("Expected 10.0.0.1, got %s", ip)
//	}
//
//	// Now this should fail.
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
//	if err == nil {
//		t.Errorf("Expected an error, received an IP: %s", ip)
//	}
//
//	if err.Error() != msgNoAvailableIP {
//		t.Errorf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
//	}
//
//	// Deallocate first IP
//	err = ipam.DeallocateIP("10.0.0.0")
//	if err != nil {
//		t.Error(err)
//	}
//
//	// This should succeed
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkBlockReuse: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//}
//
//// TestChunk32 tests bitmask size 32 - as a corner case.
//func TestChunk32(t *testing.T) {
//	// Part 1. Simple /32 block size test
//	cidr1, err := NewCIDR("10.0.0.0/24")
//	if err != nil {
//		t.Error(err)
//	}
//	network1 := Network{CIDR: cidr1,
//		BlockMask:      32,
//		AllowedTenants: []string{"*"},
//	}
//
//	networks := []Network{network1}
//	ipam, err := NewChunkIPAM(networks, testSaver.save, nil)
//	if err != nil {
//		t.Error(err)
//	}
//
//	ip, err := ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.1" {
//		t.Errorf("Expected 10.0.0.1, got %s", ip)
//	}
//
//	// Part 2. Here we add a /32 block size to a /32 CIDR.
//	cidr2, err := NewCIDR("10.0.0.0/32")
//	if err != nil {
//		t.Error(err)
//	}
//	network2 := Network{CIDR: cidr2,
//		BlockMask:      32,
//		AllowedTenants: []string{"*"},
//	}
//
//	networks = []Network{network2}
//	ipam, err = NewChunkIPAM(networks, testSaver.save, nil)
//	if err != nil {
//		t.Error(err)
//	}
//
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//
//	// Now this should fail - only one /32 block can be there on a /32 net.
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
//	if err == nil {
//		t.Errorf("Expected an error, received an IP: %s", ip)
//	}
//
//	if err.Error() != msgNoAvailableIP {
//		t.Errorf("Expected error \"%s\", got %s", msgNoAvailableIP, err)
//	}
//}
//
//// TestSegments tests that segments get different blocks.
//func TestChunkSegments(t *testing.T) {
//	cidr1, err := NewCIDR("10.0.0.0/24")
//	if err != nil {
//		t.Error(err)
//	}
//	network1 := Network{CIDR: cidr1,
//		BlockMask:      30,
//		AllowedTenants: []string{"*"},
//	}
//
//	networks := []Network{network1}
//	ipam, err := NewChunkIPAM(networks, testSaver.save, nil)
//	if err != nil {
//		t.Error(err)
//	}
//
//	ip, err := ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.0" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//
//	ip, err = ipam.AllocateIP("ten1", "seg1")
//	t.Logf("TestChunkSegments: Allocated %s for ten1:seg1", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.1" {
//		t.Errorf("Expected 10.0.0.0, got %s", ip)
//	}
//
//	// This should go into a separate chunk
//	ip, err = ipam.AllocateIP("ten1", "seg2")
//	t.Logf("TestChunkSegments: Allocated %s for ten1:seg2", ip)
//	if err != nil {
//		t.Error(err)
//	}
//	if ip.String() != "10.0.0.4" {
//		t.Errorf("Expected 10.0.0.4, got %s", ip)
//	}
//}
//

func initIpam(t *testing.T, conf string) *IPAM {
	ipam, err := NewIPAM(testSaver.save, nil)
	if err != nil {
		t.Error(err)
	}
	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(conf), &topoReq)
	if err != nil {
		t.Errorf("Cannot parse %s: %v", conf, err)
	}
	err = ipam.updateTopology(topoReq)
	if err != nil {
		t.Error(err)
	}
	return ipam
}

func TestTenants(t *testing.T) {
	conf := `
	{
    "networks" : [
        {
            "name" : "net1",
            "cidr" : "10.200.0.0/16",
            "block_mask" : 29,
            "tenants" : [ "tenant1", "tenant2" ]
        },
        {
            "name" : "net2",
            "cidr" : "10.220.0.0/16",
            "block_mask" : 28,
            "tenants" : [ "tenant3" ]
        },
        {
            "name" : "net3",
            "cidr" : "10.240.0.0/16",
            "block_mask" : 28
        }
        
    ],

    "topologies" : [
        {
            "networks" : [ "net1", "net2", "net3" ],
            "map" : [ "host1" ]
        }
     ]
     }
	`
	ipam = initIpam(t, conf)

	ip, err := ipam.AllocateIP("x1", "host1", "tenant1", "")
	if err != nil {
		t.Error(err)
	}
	if ip.String() != "10.200.0.0" {
		t.Errorf("Expected 10.200.0.0, got %s", ip.String())
	}

	ip, err = ipam.AllocateIP("x1", "host1", "tenant2", "")
	if err != nil {
		t.Error(err)
	}
	if ip.String() != "10.200.0.8" {
		t.Errorf("Expected 10.200.0.8, got %s", ip.String())
	}

	ip, err = ipam.AllocateIP("x1", "host1", "tenant3", "")
	if err != nil {
		t.Error(err)
	}
	if ip.String() != "10.220.0.0" {
		t.Errorf("Expected 10.220.0.0, got %s", ip.String())
	}

	ip, err = ipam.AllocateIP("x1", "host1", "someothertenant", "")
	if err != nil {
		t.Error(err)
	}
	if ip.String() != "10.240.0.0" {
		t.Errorf("Expected 10.240.0.0, got %s", ip.String())
	}

	// TODO allocate no host
}
