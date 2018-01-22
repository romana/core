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
	"strings"
	"testing"

	"github.com/romana/core/common/api"
	"github.com/romana/core/common/api/errors"
)

var (
	testSaver *TestSaver
	ipam      *IPAM
)

func loadTestData(t *testing.T) []byte {
	testName := t.Name()
	fileName := fmt.Sprintf("testdata/%s.json", testName)
	t.Logf("Loading data for %s from %s", testName, fileName)
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func initIpam(t *testing.T, conf string) *IPAM {
	// If not specified, load from file named after this test
	if conf == "" {
		b := loadTestData(t)
		conf = string(b)
	}
	ipam, err := NewIPAM(testSaver.save, nil)
	if err != nil {
		t.Fatalf("Error initializing ipam: %v", err)
	}
	ipam.load = testSaver.load
	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(conf), &topoReq)
	if err != nil {
		t.Fatalf("Cannot parse %s: %v", conf, err)
	}
	err = ipam.UpdateTopology(topoReq, false)
	if err != nil {
		t.Fatalf("Error updating topology: %s", err)
	}
	ipam.save(ipam, nil)
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

func (s *TestSaver) save(ipam *IPAM, ch <-chan struct{}) error {
	b, err := json.MarshalIndent(ipam, "", "  ")
	if err != nil {
		return err
	}
	s.lastJson = string(b)

	return nil
}

func (s *TestSaver) load(ipam *IPAM, ch <-chan struct{}) error {
	parsedIPAM, err := parseIPAM(s.lastJson)
	if err != nil {
		return err
	}
	parsedIPAM.save = ipam.save
	parsedIPAM.load = ipam.load
	*ipam = *parsedIPAM

	return nil
}

func TestNewCIDR(t *testing.T) {
	var err error

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
	var err error
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
	ipam.load(ipam, nil)

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
	var err error

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

// TestIPAM_DeallocateIP tests that an IP can be
// de-allocated using IP Name or Address.
func TestIPAM_DeallocateIP(t *testing.T) {
	var err error
	ipam = initIpam(t, "")
	ip, err := ipam.AllocateIP("1", "host1", "ten1", "seg1")
	t.Logf("TestIPAM_DeallocateIP: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("TestIPAM_DeallocateIP: Expected 10.0.0.0, got %s", ip)
	}

	ip, err = ipam.AllocateIP("2", "host1", "ten1", "seg1")
	t.Logf("TestIPAM_DeallocateIP: Allocated %s for ten1:seg1", ip)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.1" {
		t.Fatalf("TestIPAM_DeallocateIP: Expected 10.0.0.1, got %s", ip)
	}

	// Deallocate first IP using IP Name
	err = ipam.DeallocateIP("1")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("TestIPAM_DeallocateIP: Sucessfully Deallocated IP for ten1:seg1 using IP Name")

	// Deallocate second IP using IP Address
	err = ipam.DeallocateIP("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("TestIPAM_DeallocateIP: Sucessfully Deallocated IP for ten1:seg1 using IP Address")

	// Negative test case for test 1 above.
	err = ipam.DeallocateIP("10.0.0.0")
	if err == nil {
		t.Fatal("Expected non-nil error")
	}
	if _, ok := err.(errors.RomanaNotFoundError); !ok {
		t.Fatalf("Expected RomanaNotFoundError, got %T", err)
	}

	// Negative test case for test 2 above.
	err = ipam.DeallocateIP("2")
	if err == nil {
		t.Fatal("Expected non-nil error")
	}
	if _, ok := err.(errors.RomanaNotFoundError); !ok {
		t.Fatalf("Expected RomanaNotFoundError, got %T", err)
	}
}

func TestBlockReuseMask32(t *testing.T) {
	var err error
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
	var err error
	ipam = initIpam(t, "")

	// 1. Allocate first 4 (/30) addresses
	for i := 0; i < 4; i++ {
		addr := fmt.Sprintf("addr%d", i)
		ip, err := ipam.AllocateIP(addr, "host1", "ten1", "seg1")
		if err != nil {
			t.Fatal(err)
		}
		ipam.load(ipam, nil)
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
	err = ipam.DeallocateIP("addr2")
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
		ipam.load(ipam, nil)
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
		ipam.load(ipam, nil)
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
	ipam.load(ipam, nil)
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
	var err error

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
	// t.Log(testSaver.lastJson)

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
	// t.Log(testSaver.lastJson)

	ip, err := ipam.AllocateIP("x1", "ip-192-168-99-10", "tenant1", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.0" {
		t.Fatalf("Expected 10.0.0.0, got %s", ip.String())
	}
	// Test allocation with same name...
	ip, err = ipam.AllocateIP("x1", "ip-192-168-99-10", "tenant1", "")
	if err == nil {
		t.Fatalf("Error expected -- allocating another address with same name. got %s", ip.String())
	}
	if _, ok := err.(errors.RomanaExistsError); !ok {
		t.Fatalf("Expected errors.RomanaExistsError, got %T: %v", err, err)
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

func TestUpdateTopology(t *testing.T) {
	ipam = initIpam(t, "")

	ip0, err := ipam.AllocateIP("x1", "h1", "tenant1", "")
	if err != nil {
		t.Fatal(err)
	}
	ipam.load(ipam, nil)

	// Load the topology data again, we'll modify the object
	topo := loadTestData(t)
	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal(topo, &topoReq)
	if err != nil {
		t.Fatalf("Cannot parse %s: %v", string(topo), err)
	}
	// Modify network name and try to update topology
	topoReq.Networks[0].Name = "net2"
	topoReq.Topologies[0].Networks[0] = "net2"

	t.Logf("Updating topology to %v", topoReq)
	err = ipam.UpdateTopology(topoReq, false)
	if err != nil {
		t.Fatal(err)
	}
	ip1 := ipam.AddressNameToIP["x1"]

	if ip1.String() != ip0.String() {
		t.Fatalf("Expected new IP %s to be same as old IP %s", ip1, ip0)
	}
}

func TestUpdateTopologyInvalidBlockMask(t *testing.T) {
	config := string(loadTestData(t))

	ipam, err := NewIPAM(testSaver.save, nil)
	if err != nil {
		t.Fatalf("error initializing ipam: %v", err)
	}
	ipam.load = testSaver.load

	topologyRequest := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(config), &topologyRequest)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", config, err)
	}

	// negative test case for block mask smaller or
	// equal to network mask.
	err = ipam.UpdateTopology(topologyRequest, false)
	if err == nil {
		t.Fatal("test failed, expected an error")
	}
	if !strings.Contains(err.Error(), "invalid blockmask") {
		t.Fatalf("test case failed, expected 'invalid blockmask...', received '%s'", err)
	}

	// negative test case for block mask greater then 32
	topologyRequest.Networks[0].BlockMask = 33
	err = ipam.UpdateTopology(topologyRequest, false)
	if err == nil {
		t.Fatal("test failed, expected an error")
	}
	if !strings.Contains(err.Error(), "invalid blockmask") {
		t.Fatalf("test case failed, expected 'invalid blockmask...', received '%s'", err)
	}

	// test case for network mask < blockmask < 32
	topologyRequest.Networks[0].BlockMask = 29
	err = ipam.UpdateTopology(topologyRequest, false)
	if err != nil {
		t.Fatalf("test case failed, expected no error, received '%s'", err)
	}
}

func TestListBlocks(t *testing.T) {
	ipam = initIpam(t, "")
	// t.Log(testSaver.lastJson)

	_, err := ipam.AllocateIP("x1", "h1", "tenant1", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ipam.AllocateIP("x2", "h1", "tenant2", "")
	if err != nil {
		t.Fatal(err)
	}
	ipam.load(ipam, nil)
	br := ipam.ListAllBlocks()
	if len(br.Blocks) != 2 {
		t.Errorf("Expected 2 blocks, got %d", len(br.Blocks))
	}
	if br.Revision != 2 {
		t.Errorf("Expected revision 2, got %d", br.Revision)
	}
	t.Logf("Have %d blocks, revision %d", len(br.Blocks), br.Revision)
}

func TestParseSimpleFlatNetworkA(t *testing.T) {
	t.Log("Example 1: Simple, flat network, (a)")
	initIpam(t, "")
	t.Logf("Slide 12: Example 1: Simple, flat network JSON:\n%s\n", testSaver.lastJson)
}

func TestParseSimpleFlatNetworkB(t *testing.T) {
	t.Logf("Example 1: Simple, flat network, (b)")
	initIpam(t, "")
	t.Logf("Slide 13: Example 1: Simple, flat network:\n%s\n", testSaver.lastJson)
}

func TestParseSimpleFlatNetworkC(t *testing.T) {
	t.Logf("Example 1: Simple, flat network, (c)")
	initIpam(t, "")
	t.Logf("Slide 14: Example 1: Simple, flat network JSON:\n%s\n", testSaver.lastJson)
}

func TestParsePrefixPerHostA(t *testing.T) {
	t.Logf("Example 2: Prefix per host (a)")
	initIpam(t, "")
	t.Logf("Slide 15: Example 2: Prefix per host (a) JSON:\n%s\n", testSaver.lastJson)
}

func TestParsePrefixPerHostB(t *testing.T) {
	t.Logf("Example 2: Prefix per host (ab")
	initIpam(t, "")
	t.Logf("Slide 16: Example 2: Prefix per host (b) JSON:\n%s\n", testSaver.lastJson)
}

func TestParseMultiHostGroupsWithPrefix(t *testing.T) {
	t.Logf("Example 3: Multi-host groups + prefix")
	initIpam(t, "")
	t.Logf("Slide 17: Example 3: Multi-host groups + prefix JSON:\n%s\n", testSaver.lastJson)
}

func TestParseVPCRoutingForTwoAZs(t *testing.T) {
	t.Logf("Example 4: VPC routing for two AZs")
	initIpam(t, "")
	t.Logf("Slide 18: Example 4: VPC routing for two AZs JSON:\n%s\n", testSaver.lastJson)
}

func TestMultiNetAllocate(t *testing.T) {
	t.Logf("TestMultiNetAllocate: Test that we can have different networks for different topologies")
	ipam = initIpam(t, "")

	ip, err := ipam.AllocateIP("addr1", "host1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestMultiNetAllocate: Allocated %s for host1", ip)
	if ip.String() != "10.0.0.0" {
		t.Fatalf("TestMultiNetAllocate: Expected 10.0.0.0, got %s", ip)
	}

	ip, err = ipam.AllocateIP("addr2", "host2", "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestMultiNetAllocate: Allocated %s for host2", ip)
	if ip.String() != "11.0.0.0" {
		t.Fatalf("TestMultiNetAllocate: Expected 11.0.0.0, got %s", ip)
	}
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

func TestPrefixGenForEmptyGroups(t *testing.T) {

	t.Logf("TestPrefixGenForEmptyGroups")

	ipam = initIpam(t, "")
	// t.Logf(testSaver.lastJson)

	net1 := ipam.Networks["net1"]
	if len(net1.Group.Groups) != 2 {
		t.Fatalf("Expected exactly two top level groups")
	}

	// Checking first top-level groups
	gr1 := net1.Group.Groups[0]
	if gr1.Groups != nil {
		t.Fatalf("Expected no sub-groups in first top-level group")
	}
	if gr1.CIDR.String() != "10.0.0.0/17" {
		t.Fatalf("CIDR for first top-level group should be 10.0.0.0/17")
	}

	// Checking sub-groups in second top-level group
	gr2 := net1.Group.Groups[1]
	if gr2.CIDR.String() != "10.0.128.0/17" {
		t.Fatalf("CIDR for second top-level group should be 10.0.128.0/17")
	}
	if len(gr2.Groups) != 2 {
		t.Fatalf("Expected two sub-groups in second top-level group")
	}
	if gr2.Groups[0].CIDR.String() != "10.0.128.0/18" {
		t.Fatalf("CIDR for first sub-group should be 10.0.128.0/18")
	}
	if gr2.Groups[1].CIDR.String() != "10.0.192.0/18" {
		t.Fatalf("CIDR for second sub-group should be 10.0.192.0/18")
	}
}

func TestHostAdditionSimple(t *testing.T) {
	var err error
	t.Logf("TestHostAdditionSimple")

	ipam = initIpam(t, "")
	//	t.Logf(testSaver.lastJson)

	for i := 0; i < 4; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.10.10.1%d", i))
		name := fmt.Sprintf("host%d", i)
		host := api.Host{Name: name,
			IP: ip,
		}
		t.Logf("Adding host %s (%s)", host.Name, host.IP)
		err := ipam.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
	}

	hosts := ipam.ListHosts()
	for _, host := range hosts.Hosts {
		if host.AgentPort == 0 {
			t.Fatalf("Host Agent Port default value missing.\n")
		}
	}

	var netNames = [...]string{"net1", "net2"}

	// We should have 2 hosts in each group now.
	for i := range netNames {
		netName := netNames[i]
		net := ipam.Networks[netName]
		for _, grp := range net.Group.Groups {
			t.Logf("Net %s: Hosts in group %s: %v", netName, grp.Name, grp.Hosts)
			if len(grp.Hosts) != 2 {
				t.Fatalf("Net %s: Expected group %s to have 2 hosts, it has %d", netName, grp.Name, len(grp.Hosts))
			}
		}
	}

	// Test host removal.
	t.Logf("Removing host 'host0'")
	err = ipam.RemoveHost(api.Host{Name: "host0"})
	if err != nil {
		t.Fatal(err)
	}

	//	t.Logf(testSaver.lastJson)
	// One of the groups in each network should only have one host left now
	for i := range netNames {
		netName := netNames[i]
		net := ipam.Networks[netName]

		grp := net.Group.Groups[0]

		// This one should have 1 host left
		t.Logf("Net %s: Hosts in group %s: %v", netName, grp.Name, grp.Hosts)
		if len(grp.Hosts) != 1 {
			t.Fatalf("Net %s: Expected group %s to have 1 hosts, it has %d", netName, grp.Name, len(grp.Hosts))
		}

		grp = net.Group.Groups[1]
		t.Logf("Net %s: Hosts in group %s: %v", netName, grp.Name, grp.Hosts)
		if len(grp.Hosts) != 2 {
			t.Fatalf("Net %s: Expected group %s to have 2 hosts, it has %d", netName, grp.Name, len(grp.Hosts))
		}
	}

	// Test that it saves, loads and we can still remove a host
	ipam, err = parseIPAM(testSaver.lastJson)
	ipam.save = testSaver.save
	ipam.load = testSaver.load
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Loaded new IPAM...")

	err = ipam.RemoveHost(api.Host{Name: "host1"})
	if err != nil {
		t.Fatal(err)
	}

	net1 := ipam.Networks["net1"]
	grp := net1.Group.Groups[0]
	t.Logf("Hosts in group %s: %v", grp.Name, grp.Hosts)
	if len(grp.Hosts) != 1 {
		t.Fatalf("Expected group %s to have 1 hosts, it has %d", grp.Name, len(grp.Hosts))
	}

	grp = net1.Group.Groups[1]
	t.Logf("Hosts in group %s: %v", grp.Name, grp.Hosts)
	if len(grp.Hosts) != 1 {
		t.Fatalf("Expected group %s to have 1 hosts, it has %d", grp.Name, len(grp.Hosts))
	}

}

func TestHostAdditionTags(t *testing.T) {
	t.Logf("TestHostAdditionTags")

	ipam = initIpam(t, "")
	//	t.Logf(testSaver.lastJson)

	tags := make(map[string]string)
	tags["tier"] = "backend"
	for i := 0; i < 8; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.10.100.1%d", i))
		name := fmt.Sprintf("backend-host-%d", i)
		host := api.Host{Name: name,
			IP:   ip,
			Tags: tags,
		}
		err := ipam.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Adding host %s (%s) with tags %v", host.Name, host.IP, tags)
	}

	tags["tier"] = "frontend"
	for i := 0; i < 4; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.10.200.1%d", i))
		name := fmt.Sprintf("frontend-host-%d", i)
		host := api.Host{Name: name,
			IP:   ip,
			Tags: tags,
		}
		err := ipam.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Adding host %s (%s) with tags %v", host.Name, host.IP, tags)
	}

	// We should have 4 hosts in groups 1 and 3 and 2 in groups 2 and 4
	net1 := ipam.Networks["net1"]
	for i, grp := range net1.Group.Groups {
		if i == 0 || i == 2 {
			if len(grp.Hosts) != 4 {
				t.Fatalf("Expected group %s to have 4 hosts, it has %d", grp.Name, len(grp.Hosts))
			}
		} else {
			if len(grp.Hosts) != 2 {
				t.Fatalf("Expected group %s to have 2 hosts, it has %d", grp.Name, len(grp.Hosts))
			}
		}
		t.Logf("Hosts in group %s (%v): %v", grp.Name, grp.Assignment, grp.Hosts)
	}

	// Now for some assignments that fail, because the host doesn't have tags
	// or has the wrong ones
	host := api.Host{Name: "another-host-1",
		IP: net.ParseIP("10.10.200.99"),
	}
	err := ipam.AddHost(host)
	if err == nil {
		// We expect this one to fail
		t.Fatal(err)
	}

	tags = make(map[string]string)
	tags["unknown"] = "unknown"
	host = api.Host{Name: "another-host-2",
		IP:   net.ParseIP("10.10.200.99"),
		Tags: tags,
	}
	err = ipam.AddHost(host)
	if err == nil {
		// We expect this one to fail
		t.Fatal(err)
	}
}

func TestTenantsBug701(t *testing.T) {
	ipam = initIpam(t, "")

	h := 1
	for i := 0; i < 31; i++ {
		addr := fmt.Sprintf("addr%d", i)
		host := fmt.Sprintf("host%d", h)
		h++
		if h > 4 {
			h = 1
		}
		t.Logf("Trying to allocate an address on host %s, try %d", host, i)
		ip, err := ipam.AllocateIP(addr, host, "tenant1", "")

		if err != nil {
			t.Fatal(err)
		}
		t.Log("Host ", host, "  Addr ", i, ": ", ip.String())
	}
}

func TestOverlappingCIDRs(t *testing.T) {
	b := loadTestData(t)
	conf := string(b)

	ipam, err := NewIPAM(testSaver.save, nil)
	if err != nil {
		t.Fatalf("Error initializing ipam: %v", err)
	}
	ipam.load = testSaver.load
	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(conf), &topoReq)
	if err != nil {
		t.Fatalf("Cannot parse %s: %v", conf, err)
	}
	err = ipam.UpdateTopology(topoReq, false)
	if err == nil {
		t.Fatal("Expected an error on updating topology")
	}
	t.Logf("Got error: %s", err)
	ipam.save(ipam, nil)
}

func TestPanic(t *testing.T) {
	ipam := initIpam(t, "")
	host := api.Host{Name: "another-host-2",
		IP: net.ParseIP("100.22.0.4"),
	}
	err := ipam.AddHost(host)
	if err != nil {
		t.Fatal(err)
	}

}

func TestRepeatedNetwork(t *testing.T) {
	b := loadTestData(t)
	conf := string(b)

	ipam, err := NewIPAM(testSaver.save, nil)
	if err != nil {
		t.Fatalf("Error initializing ipam: %v", err)
	}
	ipam.load = testSaver.load
	topoReq := api.TopologyUpdateRequest{}
	err = json.Unmarshal([]byte(conf), &topoReq)
	if err != nil {
		t.Fatalf("Cannot parse %s: %v", conf, err)
	}
	err = ipam.UpdateTopology(topoReq, false)
	if err == nil {
		t.Fatal("Expected an error on updating topology")
	}
	t.Logf("Got error: %s", err)
	ipam.save(ipam, nil)
}

func TestNodeAssignment(t *testing.T) {
	t.Logf("TestFoo")

	ipam = initIpam(t, "")

	for i := 0; i < 4; i++ {
		ip := net.ParseIP(fmt.Sprintf("192.168.1.%d", i+1))
		tags := make(map[string]string)
		tags["rack"] = fmt.Sprintf("rack-%d", i+1)
		name := fmt.Sprintf("host%d", i)
		host := api.Host{
			Name: name,
			IP:   ip,
			Tags: tags,
		}
		t.Logf("Adding host %s (%s) %s", host.Name, host.IP, tags)
		err := ipam.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(ipam.Networks["rnet-1"].Group.Hosts) != 1 {
		t.Fatalf("Expected 1 host in rnet-1, got %v", ipam.Networks["rnet-1"].Group.Hosts)
	}
	if len(ipam.Networks["rnet-2"].Group.Groups[0].Hosts) != 1 {
		t.Fatalf("Expected 1 host in rnet-2 group %s, got %v", ipam.Networks["rnet-2"].Group.Groups[0].Name, ipam.Networks["rnet-2"].Group.Hosts)
	}
	if len(ipam.Networks["rnet-2"].Group.Groups[1].Hosts) != 1 {
		t.Fatalf("Expected 1 host in rnet-2 group %s, got %v", ipam.Networks["rnet-2"].Group.Groups[1].Name, ipam.Networks["rnet-2"].Group.Hosts)
	}
	if len(ipam.Networks["rnet-2"].Group.Groups[2].Hosts) != 1 {
		t.Fatalf("Expected 1 host in rnet-2 group %s, got %v", ipam.Networks["rnet-2"].Group.Groups[2].Name, ipam.Networks["rnet-2"].Group.Hosts)
	}
}

// TestHostAdd713 will test that a host can not be added to some networks but can
// to others, and this should not error out. Considering TestHostAdd713.json topology:
// If a host with tag "rack-1" is added, it should only be added to rnet-1
// (because of the groups defined in the first topology). If a host with "rack-2" is
// added, it should only be added to rnet-2 (because of the groups defined in the first
// topology).
func TestHostAdd713(t *testing.T) {
	//var err error
	t.Logf("TestHostAdd713_1")

	ipam = initIpam(t, "")

	for i := 0; i < 3; i++ {
		ip := net.ParseIP(fmt.Sprintf("192.168.1.%d", i+1))
		tags := make(map[string]string)
		tags["rack"] = fmt.Sprintf("rack-%da", i+2)
		name := fmt.Sprintf("host%d", i)
		host := api.Host{
			Name: name,
			IP:   ip,
			Tags: tags,
		}
		t.Logf("Adding host %s (%s) %s", host.Name, host.IP, tags)
		err := ipam.AddHost(host)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPredefinedHosts(t *testing.T) {
	initIpam(t, "")
	t.Log(testSaver.lastJson)
}

func TestLabelUpdate(t *testing.T) {
	var err error
	t.Logf("TestLabelUpdate")
	ipam = initIpam(t, "")

	ip := net.ParseIP("192.168.1.1")
	name := "host1"
	tags := make(map[string]string)
	tags["rack"] = "rack1"

	host := api.Host{
		Name: name,
		IP:   ip,
		Tags: tags,
	}
	t.Logf("Adding host %s", host)
	err = ipam.AddHost(host)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipam.Networks["net1"].Group.Hosts) != 1 {
		t.Fatalf("Expected 1 host in net1, got %v", ipam.Networks["net1"].Group.Hosts)
	}
	t.Logf("Added host %s", host)

	// Update tags with some irrelevant stuff
	host.Tags["foo"] = "bar"
	t.Logf("Updating host %s", host)
	err = ipam.UpdateHostLabels(host)
	if err != nil {
		t.Fatal(err)
	}

	// Update tags with incompatible assignment
	host.Tags["rack"] = "bar"
	t.Logf("Updating host %s", host)
	err = ipam.UpdateHostLabels(host)
	if err == nil {
		t.Fatal("Expected error")
	}
	t.Logf("Got expected error %s", err)
}
