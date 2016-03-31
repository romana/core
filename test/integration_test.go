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
	"fmt"
	"net"
	"strings"
	"github.com/go-check/check"
	"github.com/romana/core/agent"
	"github.com/romana/core/common"
	"github.com/romana/core/ipam"
	"github.com/romana/core/root"
	"github.com/romana/core/tenant"
	"github.com/romana/core/topology"
	"os"
	"testing"
	"time"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type MySuite struct {
	config     common.Config
	configFile string
	rootURL    string
	topoURL    string
	tenantURL  string
	ipamURL    string
}

var _ = check.Suite(&MySuite{})

func myLog(c *check.C, args ...interface{}) {
	if len(args) == 1 {
		fmt.Println(args[0])
		c.Log(args[0])
		return
	}
	fmt.Printf(args[0].(string), args[1:]...)
	c.Log(fmt.Sprintf(args[0].(string), args[1:]...))
}

// SetUpTest for now deletes all hosts from topology DB.
func (s *MySuite) SetUpTest(c *check.C) {
	// Clean up host entries for each test.
	topoDb := common.DbStore{}
	topoDb.SetConfig(s.config.Services["topology"].ServiceSpecific["store"].(map[string]interface{}))
	err := topoDb.Connect()
	if err != nil {
		c.Fatal(err)
	}
	myLog(c, "Deleting from hosts")
	topoDb.Db.Exec("DELETE FROM hosts")
	err = common.MakeMultiError(topoDb.Db.GetErrors())
	if err != nil {
		c.Fatal(err)
	}
	c.Log("OK")
}

func (s *MySuite) SetUpSuite(c *check.C) {
	dir, _ := os.Getwd()
	c.Log("Entering setup in directory", dir)

	romanaConfigFile := os.ExpandEnv("${ROMANA_CONFIG_FILE}")
	if romanaConfigFile == "" {
		romanaConfigFile = "../common/testdata/romana.sample.yaml"
	}
	c.Log("Will use config file", romanaConfigFile)
	common.MockPortsInConfig(romanaConfigFile)
	s.configFile = "/tmp/romana.yaml"
	var err error
	s.config, err = common.ReadConfig(s.configFile)
	if err != nil {
		c.Fatal(err)
	}

	c.Log("Root configuration: ", s.config.Services["root"].Common.Api.GetHostPort())

	// Starting root service
	fmt.Println("STARTING ROOT SERVICE")
	rootInfo, err := root.Run(s.configFile)
	if err != nil {
		c.Fatal(err)
	}
	s.rootURL = "http://" + rootInfo.Address
	c.Log("Root URL:", s.rootURL)

	msg := <-rootInfo.Channel
	c.Log("Root service said:", msg)
	c.Log("Waiting a bit...")
	time.Sleep(time.Second)
	
	c.Log("Creating topology schema")
	err = topology.CreateSchema(s.rootURL, true)
	if err != nil {
		c.Fatal(err)
	}
	c.Log("OK")
	
	c.Log("Creating tenant schema")
	err = tenant.CreateSchema(s.rootURL, true)
	if err != nil {
		c.Fatal(err)
	}
	c.Log("OK")

	c.Log("Creating IPAM schema")
	err = ipam.CreateSchema(s.rootURL, true)
	if err != nil {
		c.Fatal(err)
	}
	c.Log("OK")

	// Start topology service
	myLog(c, "STARTING TOPOLOGY SERVICE")
	topoInfo, err := topology.Run(s.rootURL)
	if err != nil {
		c.Error(err)
	}
	msg = <-topoInfo.Channel
	myLog(c, "Topology service said:", msg)
	s.topoURL = "http://" + topoInfo.Address

	// Start tenant service
	myLog(c, "STARTING TENANT SERVICE")
	tenantInfo, err := tenant.Run(s.rootURL)
	if err != nil {
		c.Fatal(err)
	}
	msg = <-tenantInfo.Channel
	myLog(c, "Tenant service said: %s", msg)
	s.tenantURL = "http://" + tenantInfo.Address

	myLog(c, "STARTING IPAM SERVICE")
	ipamInfo, err := ipam.Run(s.rootURL)
	if err != nil {
		c.Fatal(err)
	}
	s.ipamURL = fmt.Sprintf("http://%s", ipamInfo.Address)
	msg = <-ipamInfo.Channel
	myLog(c, "IPAM service said: ", msg)

	myLog(c, "Done with setup")
}

// Test that agent starts
func (s *MySuite) TestAgentStart(c *check.C) {
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

	client, err := common.NewRestClient(s.topoURL, common.GetDefaultRestClientConfig())
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Calling %s", s.topoURL)
	topIndex := &common.IndexResponse{}
	err = client.Get("/", &topIndex)
	if err != nil {
		c.Error(err)
	}
	c.Assert(topIndex.ServiceName, check.Equals, "topology")
	hostsRelURL := topIndex.Links.FindByRel("host-list")
	myLog(c, "Host list URL: %s", hostsRelURL)

	// Get list of hosts - should be empty for now.
	var hostList []common.HostMessage
	client.Get(hostsRelURL, &hostList)
	myLog(c, "Host list: ", hostList)
	c.Assert(len(hostList), check.Equals, 0)

	// Add host 1
	newHostReq := common.HostMessage{Ip: "10.10.10.10", RomanaIp: possibleRomanaIps[0], AgentPort: 9999, Name: "HOST1000"}
	host1 := common.HostMessage{}
	client.Post(hostsRelURL, newHostReq, &host1)
	myLog(c, "Response: %s", host1)
	c.Assert(host1.Ip, check.Equals, "10.10.10.10")
	c.Assert(host1.Id, check.Equals, "1")

	// Add host 2
	newHostReq = common.HostMessage{Ip: "10.10.10.11", RomanaIp: possibleRomanaIps[1], AgentPort: 9999, Name: "HOST2000"}
	host2 := common.HostMessage{}
	client.Post(hostsRelURL, newHostReq, &host2)
	myLog(c, "Response: %s", host2)
	c.Assert(host2.Ip, check.Equals, "10.10.10.11")
	c.Assert(host2.Id, check.Equals, "2")

	// Get list of hosts - should have 2 now
	var hostList2 []common.HostMessage
	client.Get(hostsRelURL, &hostList2)
	myLog(c, "Host list: ", hostList2)
	c.Assert(len(hostList2), check.Equals, 2)

	myLog(c, "STARTING Agent SERVICE")
	agentInfo, err := agent.Run(s.rootURL, true)
	if err != nil {
		c.Error(err)
	}
	msg := <-agentInfo.Channel
	myLog(c, "Agent service said:", msg)
}

// Test the interaction of root/topo/tenant/ipam
func (s *MySuite) TestRootTopoTenantIpamInteraction(c *check.C) {
	myLog(c, "Entering TestRootTopoTenantIpamInteraction()")

	// 1. Add some hosts to topology service and test.
	client, err := common.NewRestClient(s.topoURL, common.GetDefaultRestClientConfig())
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Calling %s", s.topoURL)
	topIndex := &common.IndexResponse{}
	err = client.Get("/", &topIndex)
	if err != nil {
		c.Error(err)
	}
	c.Assert(topIndex.ServiceName, check.Equals, "topology")
	hostsRelURL := topIndex.Links.FindByRel("host-list")
	myLog(c, "Host list URL: %s", hostsRelURL)

	// Get list of hosts - should be empty for now.
	var hostList []common.HostMessage
	client.Get(hostsRelURL, &hostList)
	myLog(c, "Host list: ", hostList)
	c.Assert(len(hostList), check.Equals, 0)

	// Add host 1
	newHostReq := common.HostMessage{Ip: "10.10.10.10", RomanaIp: "10.0.0.0/16", AgentPort: 9999, Name: "HOST1000"}
	host1 := common.HostMessage{}
	client.Post(hostsRelURL, newHostReq, &host1)
	myLog(c, "Response: %s", host1)
	c.Assert(host1.Ip, check.Equals, "10.10.10.10")

	// Add host 2
	newHostReq = common.HostMessage{Ip: "10.10.10.11", RomanaIp: "10.1.0.0/16", AgentPort: 9999, Name: "HOST2000"}
	host2 := common.HostMessage{}
	client.Post(hostsRelURL, newHostReq, &host2)
	myLog(c, "Response: %s", host2)
	c.Assert(host2.Ip, check.Equals, "10.10.10.11")

	// Get list of hosts - should have 2 now
	var hostList2 []common.HostMessage
	client.Get(hostsRelURL, &hostList2)
	myLog(c, "Host list: ", hostList2)
	c.Assert(len(hostList2), check.Equals, 2)

	// 4. Add a tenant and a segment
	err = client.NewUrl(s.tenantURL)
	if err != nil {
		c.Error(err)
	}

	// Add tenant t1
	t1In := tenant.Tenant{Name: "t1"}
	t1Out := tenant.Tenant{}
	err = client.Post("/tenants", t1In, &t1Out)
	if err != nil {
		c.Error(err)
	}
	t1Id := t1Out.Id
	c.Assert(t1Out.Seq, check.Equals, uint64(1))
	myLog(c, "Tenant 1", t1Out)

	// Add tenant t2
	t2In := tenant.Tenant{Name: "t2"}
	t2Out := tenant.Tenant{}
	err = client.Post("/tenants", t2In, &t2Out)
	if err != nil {
		c.Error(err)
	}
	t2Id := t2Out.Id
	c.Assert(t2Out.Seq, check.Equals, uint64(2))
	myLog(c, "Tenant 2", t2Out)

	// Find first tenant
	t1OutFound := tenant.Tenant{}
	tenant1Path := fmt.Sprintf("/tenants/%d", t1Id)
	err = client.Get(tenant1Path, &t1OutFound)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Found", t1OutFound)

	// Add segment s1 to tenant t1
	t1s1In := tenant.Segment{Name: "s1", TenantId: t1Id}
	t1s1Out := tenant.Segment{}
	err = client.Post(tenant1Path+"/segments", t1s1In, &t1s1Out)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s1 to t1: ", t1s1Out)

	// Add segment s2 to tenant t1
	t1s2In := tenant.Segment{Name: "s2", TenantId: t1Id}
	t1s2Out := tenant.Segment{}
	err = client.Post(tenant1Path+"/segments", t1s2In, &t1s2Out)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s2 to t1: ", t1s2Out)

	// Add segment s1 to tenant t2
	tenant2Path := fmt.Sprintf("/tenants/%d", t2Id)
	t2s1In := tenant.Segment{Name: "s1", TenantId: t2Id}
	t2s1Out := tenant.Segment{}
	err = client.Post(tenant2Path+"/segments", t2s1In, &t2s1Out)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s1 to t2: ", t2s1Out)

	// Add segment s2 to tenant t2
	t2s2In := tenant.Segment{Name: "s2", TenantId: t2Id}
	t2s2Out := tenant.Segment{}
	err = client.Post(tenant2Path+"/segments", t2s2In, &t2s2Out)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s2 to t2: ", t2s2Out)

	// Get IP for t1, s1, h1
	myLog(c, "IPAM Test: Get first IP")
	tenantId := fmt.Sprintf("%d", t1Out.Id)
	segmentId := fmt.Sprintf("%d", t1s1Out.Id)
	t1s1h1EpIn := ipam.Endpoint{Name: "endpoint1", TenantId: tenantId, SegmentId: segmentId, HostId: host1.Id}
	t1s1h1Ep1Out := ipam.Endpoint{}
	client.NewUrl(s.ipamURL)
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep1Out)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "IPAM Test: Response from IPAM for %v is %v", t1s1h1EpIn, t1s1h1Ep1Out)
	c.Assert(t1s1h1Ep1Out.Ip, check.Equals, "10.0.0.3")

	// Get another IP for t1, s1, h1
	t1s1h1Ep2Out := ipam.Endpoint{}
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep2Out)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "IPAM Test: Response from IPAM for %v is %v", t1s1h1EpIn, t1s1h1Ep2Out)
	c.Assert(t1s1h1Ep2Out.Ip, check.Equals, "10.0.0.4")

	// And another one for t1, s1, h1
	t1s1h1Ep3Out := ipam.Endpoint{}
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep3Out)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "IPAM Test: Response from IPAM for %v is %v ", t1s1h1EpIn, t1s1h1Ep3Out)
	c.Assert(t1s1h1Ep3Out.Ip, check.Equals, "10.0.0.5")

	// Try deleting second...
	myLog(c, "IPAM Test: Trying to delete IP %s", t1s1h1Ep2Out.Ip)
	delOut := ipam.Endpoint{}
	err = client.Delete(fmt.Sprintf("/endpoints/%s", t1s1h1Ep2Out.Ip), nil, &delOut)
	if err != nil {
		c.Error(err)
	}
	c.Assert(delOut.Ip, check.Equals, t1s1h1Ep2Out.Ip)
	myLog(c, "IPAM Test: Deletion returned %v", delOut)

	// And add another one for t1, s1, h1
	t1s1h1Ep4Out := ipam.Endpoint{}
	err = client.Post("/endpoints", t1s1h1EpIn, &t1s1h1Ep4Out)
	if err != nil {
		c.Error(err)
	}
	// Assert that this is the same as the deleted one.
	c.Assert(delOut.Ip, check.Equals, t1s1h1Ep4Out.Ip)
	myLog(c, "IPAM Test: Response from IPAM for %v is %v", t1s1h1EpIn, t1s1h1Ep4Out)

	// Get IP for t2, s2, h2
	tenantId = fmt.Sprintf("%d", t2Out.Id)
	segmentId = fmt.Sprintf("%d", t2s2Out.Id)
	t2s2h2EpIn := ipam.Endpoint{Name: "endpoint1", TenantId: tenantId, SegmentId: segmentId, HostId: host2.Id}
	t2s2h2EpOut := ipam.Endpoint{}
	err = client.Post("/endpoints", t2s2h2EpIn, &t2s2h2EpOut)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Response from IPAM for %v is %v", t2s2h2EpIn, t2s2h2EpOut)
	// Expecting 17 because tenant 2 and segment 2: 1 << 12 | 1 << 4
	c.Assert(t2s2h2EpOut.Ip, check.Equals, "10.1.17.3")

	// Try legacy request
	endpointOut := ipam.Endpoint{}
	legacyURL := "/allocateIpByName?tenantName=t1&segmentName=s1&hostName=HOST2000&instanceName=bla"
	myLog(c, "Calling legacy URL", legacyURL)

	err = client.Get(legacyURL, &endpointOut)

	if err != nil {
		myLog(c, "Error %s\n", err)
		c.Error(err)
	}
	myLog(c, "Legacy received:", endpointOut)
	myLog(c, "Legacy IP:", endpointOut.Ip)
}
