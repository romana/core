// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Test
package test

import (
	//	"database/sql"

	"encoding/json"
	"fmt"
	"github.com/go-check/check"
	"github.com/pborman/uuid"
	"github.com/romana/core/agent"
	"github.com/romana/core/common"
	"github.com/romana/core/ipam"
	"github.com/romana/core/root"
	"github.com/romana/core/tenant"
	"github.com/romana/core/topology"
	"net"
	"net/http"
	"os"
	"runtime"
	//	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	// How many times SetUpTest was called...
	setupCnt = 0
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type urlInfo struct {
	rootURL   string
	topoURL   string
	tenantURL string
	ipamURL   string
}

type MySuite struct {
	common.RomanaTestSuite
	urlInfos map[string]urlInfo
}

var _ = check.Suite(&MySuite{})

func (s *MySuite) SetUpSuite(c *check.C) {
	s.urlInfos = make(map[string]urlInfo)
}

func (s *MySuite) TearDownSuite(c *check.C) {
	s.RomanaTestSuite.CleanUp()
}

func myLog(c *check.C, args ...interface{}) {
	if len(args) == 1 {
		c.Log(fmt.Sprintf("%s: %v\n", c.TestName(), args[0]))
		return
	}
	newArgs := make([]interface{}, len(args)-1)
	for i, a := range args[1:] {
		switch a := a.(type) {
		default:
			j, err := json.Marshal(a)
			if err == nil {
				newArgs[i] = fmt.Sprintf("%T: %s", a, j)
			} else {
				newArgs[i] = fmt.Sprintf("%s", a)
			}
		case bool:
			newArgs[i] = a
		case int:
			newArgs[i] = a
		case uint:
			newArgs[i] = a
		case uint64:
			newArgs[i] = a
		case string:
			newArgs[i] = a
		}
	}
	fmtStr := fmt.Sprintf("%s: %s\n", c.TestName(), args[0].(string))
	c.Logf(fmtStr, newArgs...)
}

func (s *MySuite) SetUpTest(c *check.C) {

	dir, _ := os.Getwd()
	c.Log("integration_test.SetUpSuite(): Entering setup in directory", dir)
	err := s.RomanaTestSuite.MockConfig(common.DefaultTestConfigFile)
	if err != nil {
		c.Fatal(err)
	}
	c.Log("integration_test.SetUpSuite(): Root configuration: ", s.RomanaTestSuite.Config.Services["root"].Common.Api.GetHostPort())

	// Starting root service
	fmt.Printf("integration_test.SetUpSuite(): Starting root service with %s\n", s.RomanaTestSuite.ConfigFile)
	rootInfo, err := root.Run(s.RomanaTestSuite.ConfigFile)
	if err != nil {
		c.Fatal(err)
	}

	urlInfo := urlInfo{}
	urlInfo.rootURL = "http://" + rootInfo.Address
	c.Log("integration_test.SetUpSuite(): Root URL:", urlInfo.rootURL)

	msg := <-rootInfo.Channel
	c.Log("integration_test.SetUpSuite(): Root service said:", msg)
	c.Log("integration_test.SetUpSuite(): Waiting a bit...")
	time.Sleep(time.Second)

	c.Log("Creating topology schema")
	topo := &topology.TopologySvc{}
	err = common.SimpleOverwriteSchema(topo, urlInfo.rootURL, nil)
	if err != nil {
		c.Fatalf("Error: [%s] %T", err, err)
	}

	c.Log("Creating tenant schema")
	ten := &tenant.TenantSvc{}
	err = common.SimpleOverwriteSchema(ten, urlInfo.rootURL, nil)

	if err != nil {
		c.Fatal(err)
	}
	c.Log("integration_test.SetUpSuite(): OK")

	c.Log("Creating IPAM schema")
	ipam := &ipam.IPAM{}
	err = common.SimpleOverwriteSchema(ipam, urlInfo.rootURL, nil)

	if err != nil {
		c.Fatal(err)
	}

	// Start topology service
	myLog(c, "STARTING TOPOLOGY SERVICE")
	topoInfo, err := common.SimpleStartService(topo, urlInfo.rootURL, nil)
	if err != nil {
		c.Error(err)
	}
	msg = <-topoInfo.Channel
	myLog(c, "integration_test.SetUpSuite(): Topology service said:", msg)
	urlInfo.topoURL = "http://" + topoInfo.Address

	// Start tenant service
	myLog(c, "STARTING TENANT SERVICE")
	tenantInfo, err := common.SimpleStartService(ten, urlInfo.rootURL, nil)
	if err != nil {
		c.Fatal(err)
	}
	msg = <-tenantInfo.Channel
	myLog(c, "integration_test.SetUpSuite(): Tenant service said: %s", msg)
	urlInfo.tenantURL = "http://" + tenantInfo.Address

	myLog(c, "STARTING IPAM SERVICE")
	ipamInfo, err := common.SimpleStartService(ipam, urlInfo.rootURL, nil)
	if err != nil {
		c.Fatal(err)
	}
	urlInfo.ipamURL = fmt.Sprintf("http://%s", ipamInfo.Address)
	msg = <-ipamInfo.Channel
	myLog(c, "integration_test.SetUpSuite(): IPAM service said: %s", msg)

	testName := c.TestName()
	s.urlInfos[testName] = urlInfo

	myLog(c, "integration_test.SetUpSuite(): Done with setup")
}

// Test that agent starts
func (s *MySuite) TestAgentStart(c *check.C) {
	urlInfo := s.urlInfos[c.TestName()]
	myLog(c, "integration_test: Entering TestAgentStart")
	if runtime.GOOS != "linux" {
		c.Errorf("Unsupported platform: %s", runtime.GOOS)
		c.FailNow()
	}
	// Find some romana IPs that we can use... Because the agent checks for those
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		c.Error(err)
	}
	possibleRomanaIps := make([]string, 0)
	for _, addr := range addrs {
		strAddr := addr.String()
		// Ignore IPv6 for now...
		if strings.ContainsAny(strAddr, ":") {
			continue
		}
		possibleRomanaIps = append(possibleRomanaIps, strAddr)
	}

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(urlInfo.topoURL, nil))
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Calling %s", urlInfo.topoURL)
	topIndex := &common.IndexResponse{}
	err = client.Get("/", &topIndex)
	if err != nil {
		c.Error(err)
	}
	c.Assert(topIndex.ServiceName, check.Equals, "topology")
	hostsRelURL := topIndex.Links.FindByRel("host-list")
	myLog(c, "Host list URL: %s", hostsRelURL)

	// Get list of hosts - should be empty for now.
	var hostList []common.Host
	client.Get(hostsRelURL, &hostList)
	myLog(c, "Host list: (expecting 0): %s", hostList)
	c.Assert(len(hostList), check.Equals, 0)

	// Add host 1
	newHostReq := common.Host{Ip: "10.10.10.10", RomanaIp: possibleRomanaIps[0], AgentPort: 9999, Name: "HOST1000"}
	host1 := common.Host{}
	client.Post(hostsRelURL, newHostReq, &host1)
	myLog(c, "Response: %s", host1)
	c.Assert(host1.Ip, check.Equals, "10.10.10.10")
	c.Assert(host1.ID, check.Equals, uint64(1))

	// Add host 2
	newHostReq = common.Host{Ip: "10.10.10.11", RomanaIp: possibleRomanaIps[1], AgentPort: 9999, Name: "HOST2000"}
	host2 := common.Host{}
	client.Post(hostsRelURL, newHostReq, &host2)
	myLog(c, "Response: %s", host2)
	c.Assert(host2.Ip, check.Equals, "10.10.10.11")
	c.Assert(host2.ID, check.Equals, uint64(2))

	// Get list of hosts - should have 2 now
	var hostList2 []common.Host
	client.Get(hostsRelURL, &hostList2)
	myLog(c, "Hosts list: (expecting 2): %d %v", len(hostList2), hostList2)
	c.Assert(len(hostList2), check.Equals, 2)

	myLog(c, "STARTING Agent SERVICE")

	a := &agent.Agent{TestMode: true}
	helper := agent.NewAgentHelper(a)
	a.Helper = &helper
	agentInfo, err := common.SimpleStartService(a, urlInfo.rootURL, nil)
	if err != nil {
		c.Error(err)
	}
	msg := <-agentInfo.Channel
	myLog(c, "Agent service said: %s", msg)
}

func (s *MySuite) TestConcurrentReads(c *check.C) {
	urlInfo := s.urlInfos[c.TestName()]
	myLog(c, "integration_test: Entering TestConcurrentReads")
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(urlInfo.rootURL, nil))
	client.NewUrl(urlInfo.tenantURL)
	if err != nil {
		c.Error(err)
	}
	// Add tenant t1
	t1In := tenant.Tenant{Name: "conc_name1", ExternalID: "conc_t1"}
	t1Out := tenant.Tenant{}
	err = client.Post("/tenants", t1In, &t1Out)
	if err != nil {
		c.Error(err)
	}
	t1ExtID := t1In.ExternalID
	c.Assert(t1Out.NetworkID, check.Equals, uint64(0))
	c.Assert(t1ExtID, check.Equals, "conc_t1")
	myLog(c, "Tenant 1 %s\n", t1Out)

	// Find by external ID a number of times.
	numTries := 500
	myLog(c, "Trying to find exactly one external_id=t1 %d times\n", numTries)
	var wg sync.WaitGroup

	f := func() {
		defer wg.Done()
		toFind := tenant.Tenant{ExternalID: "t1"}
		err = client.Find(&toFind, common.FindExactlyOne)
		if err != nil {
			c.Error(err)
		}
		c.Assert(toFind.Name, check.Equals, "name1")
		c.Assert(toFind.ExternalID, check.Equals, "t1")
		c.Assert(toFind.NetworkID, check.Equals, uint64(0))
	}
	wg.Add(numTries)
	for i := 0; i < numTries; i++ {
		go f()
	}
	myLog(c, "Trying to find exactly one external_id=t1 %d times: OK!!!\n", numTries)

}

// Test the interaction of root/topo/tenant/ipam
func (s *MySuite) TestRootTopoTenantIpamInteraction(c *check.C) {
	urlInfo := s.urlInfos[c.TestName()]
	myLog(c, "integration_test: Entering TestRootTopoTenantIpamInteraction()")

	// 1. Add some hosts to topology service and test.
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(urlInfo.rootURL, nil))
	if err != nil {
		c.Error(err)
	}

	myLog(c, "Calling %s", urlInfo.topoURL)
	client.NewUrl(urlInfo.topoURL)
	topIndex := &common.IndexResponse{}
	err = client.Get("/", &topIndex)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(topIndex.ServiceName, check.Equals, "topology")
	hostsRelURL := topIndex.Links.FindByRel("host-list")
	myLog(c, "Host list URL: %s", hostsRelURL)

	// Get list of hosts - should be empty for now.
	var hostList []common.Host
	err = client.Get(hostsRelURL, &hostList)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Host list (expecting empty): %d %v", len(hostList), hostList)
	c.Assert(len(hostList), check.Equals, 0)

	// Add host 1
	newHostReq := common.Host{Ip: "10.10.10.10", RomanaIp: "10.0.0.0/16", AgentPort: 9999, Name: "HOST1000"}
	host1 := common.Host{}
	err = client.Post(hostsRelURL, newHostReq, &host1)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Response: %s", host1)
	c.Assert(host1.Ip, check.Equals, "10.10.10.10")

	// Get list of hosts - should have 1 now
	var hostList1 []common.Host
	err = client.Get(hostsRelURL, &hostList1)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Host list (expecting 1): %d %v", len(hostList1), hostList1)
	c.Assert(len(hostList1), check.Equals, 1)

	// Add host 2
	newHostReq = common.Host{Ip: "10.10.10.11", RomanaIp: "10.1.0.0/16", AgentPort: 9999, Name: "HOST2000"}
	host2 := common.Host{}
	err = client.Post(hostsRelURL, newHostReq, &host2)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Response: %s", host2)
	c.Assert(host2.Ip, check.Equals, "10.10.10.11")

	// Get list of hosts - should have 2 now
	var hostList2 []common.Host
	err = client.Get(hostsRelURL, &hostList2)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Host list (expecting 2): %d %v", len(hostList2), hostList2)
	c.Assert(len(hostList2), check.Equals, 2)

	// 4. Add a tenant and a segment
	err = client.NewUrl(urlInfo.tenantURL)
	if err != nil {
		c.Error(err)
	}

	// Add tenant t1
	t1In := tenant.Tenant{Name: "name1", ExternalID: "t1"}
	t1Out := tenant.Tenant{}
	err = client.Post("/tenants", t1In, &t1Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	t1Id := t1Out.ID
	c.Assert(t1Out.NetworkID, check.Equals, uint64(0))
	myLog(c, "Tenant 1 %s\n", t1Out)

	// Find by name
	err = client.Get("/findExactlyOne/tenants?name=name1", &t1Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(t1Out.Name, check.Equals, "name1")
	c.Assert(t1Out.ExternalID, check.Equals, "t1")

	// Add tenant with same external ID -- should result in a conflict
	tConflictIn := tenant.Tenant{ExternalID: "t1"}
	tConflictOut := tenant.Tenant{}
	err = client.Post("/tenants", tConflictIn, &tConflictOut)
	c.Assert(err.(common.HttpError).StatusCode, check.Equals, http.StatusConflict)

	// Add tenant with same name, different external ID
	t2In := tenant.Tenant{Name: "name1", ExternalID: "t2"}
	t2Out := tenant.Tenant{}
	err = client.Post("/tenants", t2In, &t2Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	t2Id := t2Out.ID
	c.Assert(t2Out.ExternalID, check.Equals, "t2")
	c.Assert(t2Out.NetworkID, check.Equals, uint64(1))
	myLog(c, "Tenant 2 %s", t2Out)

	tenSingle := tenant.Tenant{}
	tenSingle.Name = "name1"
	// Find by name - should be an error for findOne (there's 2 of them)
	err = client.Find(&tenSingle, common.FindExactlyOne)
	if err == nil {
		c.Error(fmt.Sprintf("Expected error %s", err))
		c.FailNow()
	} else {
		myLog(c, "Expected error %s\n", err)
	}

	// FindFirst
	tenSingle = tenant.Tenant{}
	tenSingle.Name = "name1"
	err = client.Find(&tenSingle, common.FindFirst)
	if err != nil {
		c.Fatal(err)

	}
	c.Assert(tenSingle.Name, check.Equals, "name1")
	c.Assert(tenSingle.ExternalID, check.Equals, "t1")

	// FindLast
	tenSingle = tenant.Tenant{}
	tenSingle.Name = "name1"
	err = client.Find(&tenSingle, common.FindLast)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(tenSingle.Name, check.Equals, "name1")
	c.Assert(tenSingle.ExternalID, check.Equals, "t2")

	// findAll should find 2 tenants.
	//	tenants := []tenant.Tenant{tenant.Tenant{}}
	var tenants []tenant.Tenant
	err = client.Find(&tenants, common.FindAll)
	c.Assert(len(tenants), check.Equals, 2)
	c.Assert(tenants[0].Name, check.Equals, "name1")
	c.Assert(tenants[0].ExternalID, check.Equals, "t1")
	c.Assert(tenants[1].Name, check.Equals, "name1")
	c.Assert(tenants[1].ExternalID, check.Equals, "t2")

	// Find first tenant
	t1OutFound := tenant.Tenant{}
	tenant1Path := fmt.Sprintf("/tenants/%d", t1Id)
	err = client.Get(tenant1Path, &t1OutFound)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(t1OutFound.Name, check.Equals, "name1")
	c.Assert(t1OutFound.ExternalID, check.Equals, "t1")
	myLog(c, "Found %s", t1OutFound)

	// Add tenant with same name, different external ID
	t3In := tenant.Tenant{Name: "name2", ExternalID: "t3"}
	t3Out := tenant.Tenant{}
	err = client.Post("/tenants", t3In, &t3Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(t3Out.Name, check.Equals, "name2")
	c.Assert(t3Out.ExternalID, check.Equals, "t3")
	c.Assert(t3Out.NetworkID, check.Equals, uint64(2))
	myLog(c, "Tenant 3 %s", t3Out)

	// findAll should find 1 tenants with name "name2"
	tenants = []tenant.Tenant{tenant.Tenant{Name: "name2"}}
	err = client.Find(&tenants, common.FindAll)
	c.Assert(len(tenants), check.Equals, 1)
	c.Assert(tenants[0].Name, check.Equals, "name2")
	c.Assert(tenants[0].ExternalID, check.Equals, "t3")

	// Add segment s1 to tenant t1
	tenant1SegmentPath := tenant1Path + "/segments"
	tenant1ExtIDSegmentPath := tenant1Path + "/segments"
	t1s1In := tenant.Segment{Name: "s1", ExternalID: "s1", TenantID: t1Id}
	t1s1Out := tenant.Segment{}
	err = client.Post(tenant1SegmentPath, t1s1In, &t1s1Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Added segment s1 to t1: %s", t1s1Out)

	// List segments
	var segments []tenant.Segment
	err = client.Get(tenant1SegmentPath, &segments)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(len(segments), check.Equals, 1)
	myLog(c, "Segments list: expected 1 at  %s: %d %s", tenant1SegmentPath, len(segments), segments)

	// List segments using tenant external ID.
	err = client.Get(tenant1ExtIDSegmentPath, &segments)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(len(segments), check.Equals, 1)
	myLog(c, "Segments list: expected 1 at  %s: %d %s", tenant1ExtIDSegmentPath, len(segments), segments)

	// Add segment s2 to tenant t1
	t1s2In := tenant.Segment{Name: "s2", ExternalID: "s2", TenantID: t1Id}
	t1s2Out := tenant.Segment{}
	err = client.Post(tenant1Path+"/segments", t1s2In, &t1s2Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Added segment s2 to t1: %s", t1s2Out)

	err = client.Get(tenant1SegmentPath, &segments)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(len(segments), check.Equals, 2)
	myLog(c, "Segments list: expected 2 at %s: %d %s", tenant1SegmentPath, len(segments), segments)

	// Add segment s1 to tenant t2
	tenant2Path := fmt.Sprintf("/tenants/%d", t2Id)
	t2s1In := tenant.Segment{ExternalID: "s1", Name: "s1", TenantID: t2Id}
	t2s1Out := tenant.Segment{}
	err = client.Post(tenant2Path+"/segments", t2s1In, &t2s1Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Added segment s1 to t2: %s", t2s1Out)

	// Add segment s2 to tenant t2
	t2s2In := tenant.Segment{ExternalID: "s2", Name: "s2", TenantID: t2Id}
	t2s2Out := tenant.Segment{}
	err = client.Post(tenant2Path+"/segments", t2s2In, &t2s2Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Added segment s2 to t2: %s", t2s2Out)

	// Add segment s3 to tenant t3
	t3s3In := tenant.Segment{Name: "s3", ExternalID: "s3", TenantID: t3Out.ID}
	t3s3Out := tenant.Segment{}
	err = client.Post(fmt.Sprintf("/tenants/%d/segments", t3Out.ID), t3s3In, &t3s3Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Added segment s3 to t3: %s", t3s3Out)

	// Get IP for t1, s1, h1
	myLog(c, "IPAM Test: Get first IP")
	tenantId := fmt.Sprintf("%d", t1Out.ID)
	segmentId := fmt.Sprintf("%d", t1s1Out.ID)
	t1s1h1EpIn := ipam.Endpoint{Name: "endpoint1", TenantID: tenantId, SegmentID: segmentId, HostId: fmt.Sprintf("%d", host1.ID)}
	t1s1h1EpIn.RequestToken = common.SqlNullStringUuid()
	t1s1h1Ep1Out := ipam.Endpoint{}
	client.NewUrl(urlInfo.ipamURL)
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep1Out)
	myLog(c, "Posting %v to /endpoints: %v", t1s1h1EpIn, err)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "IPAM Test: Response from IPAM for %s is %s, #1", t1s1h1EpIn, t1s1h1Ep1Out)
	c.Assert(t1s1h1Ep1Out.Ip, check.Equals, "10.0.0.3")

	// Get another IP for t1, s1, h1
	t1s1h1Ep2Out := ipam.Endpoint{}
	t1s1h1EpIn.Name = "endpoint2"
	t1s1h1EpIn.RequestToken = common.SqlNullStringUuid()
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep2Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "IPAM Test: Response from IPAM for %s is %s, #2", t1s1h1EpIn, t1s1h1Ep2Out)
	c.Assert(t1s1h1Ep2Out.Ip, check.Equals, "10.0.0.4")

	// And another one for t1, s1, h1
	t1s1h1EpIn.Name = "endpoint3"
	t1s1h1EpIn.RequestToken = common.SqlNullStringUuid()
	t1s1h1Ep3Out := ipam.Endpoint{}
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep3Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "IPAM Test: Response from IPAM for %s is %s, #3", t1s1h1EpIn, t1s1h1Ep3Out)
	c.Assert(t1s1h1Ep3Out.Ip, check.Equals, "10.0.0.5")

	// Try deleting second...
	myLog(c, "IPAM Test: Trying to delete IP %s", t1s1h1Ep2Out.Ip)
	delOut := ipam.Endpoint{}
	err = client.Delete(fmt.Sprintf("/endpoints/%s", t1s1h1Ep2Out.Ip), nil, &delOut)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	c.Assert(delOut.Ip, check.Equals, t1s1h1Ep2Out.Ip)
	myLog(c, "IPAM Test: Deletion returned %s", delOut)

	// Add a few more, to fill in the remaining bits, so we
	// can start reusing the IP deleted above.
	// Remember, we allocated up to 5, so start with 6.
	for i := 6; i < (1 << 8); i++ {
		myLog(c, "IPAM Test: Allocating IP for %s/%s, endpoint %d", t1s1h1EpIn.TenantID, t1s1h1EpIn.SegmentID, i)
		t1s1h1EpXOut := ipam.Endpoint{}
		t1s1h1EpIn.Name = fmt.Sprintf("endpoint%d", i)
		t1s1h1EpIn.RequestToken = common.SqlNullStringUuid()
		err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1EpXOut)
		if err != nil {
			c.Error(err)
			c.FailNow()
		}
		myLog(c, "IPAM Test: Got %s", t1s1h1EpXOut.Ip)
	}

	// Now, add another one for t1, s1, h1
	t1s1h1Ep4Out := ipam.Endpoint{}
	t1s1h1EpIn.Name = "endpointFinal"
	t1s1h1EpIn.RequestToken = common.SqlNullStringUuid()
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep4Out)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	// Assert that this is the same as the deleted one above.
	c.Assert(delOut.Ip, check.Equals, t1s1h1Ep4Out.Ip)
	myLog(c, "IPAM Test: Response from IPAM for %s is %s", t1s1h1EpIn, t1s1h1Ep4Out)

	// Get IP for t2, s2, h2
	tenantId = fmt.Sprintf("%d", t2Out.ID)
	segmentId = fmt.Sprintf("%d", t2s2Out.ID)
	t2s2h2EpIn := ipam.Endpoint{Name: "endpointT2S2H2", TenantID: tenantId, SegmentID: segmentId, HostId: fmt.Sprintf("%d", host2.ID)}
	t2s2h2EpIn.RequestToken = common.SqlNullStringUuid()
	t2s2h2EpOut := ipam.Endpoint{}
	err = client.Post("/endpoints", t2s2h2EpIn, &t2s2h2EpOut)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Response from IPAM for %s is %s", t2s2h2EpIn, t2s2h2EpOut)
	// Expecting 17 because tenant 2 and segment 2: 1 << 12 | 1 << 4
	c.Assert(t2s2h2EpOut.Ip, check.Equals, "10.1.17.3")

	// Try legacy request using tenantID
	endpointOut := ipam.Endpoint{}
	legacyURL := "/allocateIP?tenantID=t1&segmentName=s1&hostName=HOST2000&instanceName=bla&" + common.RequestTokenQueryParameter + "=" + uuid.New()
	myLog(c, "Calling legacy URL %s", legacyURL)
	err = client.Get(legacyURL, &endpointOut)
	if err != nil {
		myLog(c, "Error %s\n", err)
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Legacy received: %s", endpointOut)
	myLog(c, "Legacy IP: %s", endpointOut.Ip)

	// Try legacy request using tenantName
	endpointOut = ipam.Endpoint{}
	legacyURL = "/allocateIP?tenantName=name2&segmentName=s3&hostName=HOST2000&instanceName=bla&" + common.RequestTokenQueryParameter + "=" + uuid.New()
	myLog(c, "Calling legacy URL %s", legacyURL)
	//	time.Sleep(time.Hour)
	err = client.Get(legacyURL, &endpointOut)
	if err != nil {
		myLog(c, "Error %s\n", err)
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Legacy received: %s", endpointOut)
	myLog(c, "Legacy IP: %s", endpointOut.Ip)
}
