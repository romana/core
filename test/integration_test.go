// Copyright (c) 2015 Pani Networks
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
	"fmt"
	"github.com/go-check/check"
	"github.com/romana/core/agent"
	"github.com/romana/core/common"
	"github.com/romana/core/ipam"
	"github.com/romana/core/root"
	"github.com/romana/core/tenant"
	"github.com/romana/core/topology"
	"os"
	//	"reflect"
	"testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type MySuite struct {
	config     common.Config
	configFile string
	rootUrl    string
}

var _ = check.Suite(&MySuite{})

func (s *MySuite) SetUpTest(c *check.C) {
	dir, _ := os.Getwd()
	c.Log("Entering setup in directory", dir)
	s.configFile = "../common/testdata/romana.sample.yaml"
	var err error
	s.config, err = common.ReadConfig(s.configFile)
	if err != nil {
		panic(err)
	}
	c.Log("Root configuration: ", s.config.Services["root"].Common.Api.GetHostPort())
	s.rootUrl = "http://" + s.config.Services["root"].Common.Api.GetHostPort()
	c.Log("Root URL:", s.rootUrl)

	// Starting root service
	fmt.Println("STARTING ROOT SERVICE")
	channelRoot, err := root.Run(s.configFile)
	if err != nil {
		c.Error(err)
	}
	msg := <-channelRoot
	c.Log("Root service said:", msg)

	c.Log("Creating topology schema")
	err = topology.CreateSchema(s.rootUrl, true)
	if err != nil {
		c.Fatal(err)
	}
	c.Log("OK")

	c.Log("Creating tenant schema")
	err = tenant.CreateSchema(s.rootUrl, true)
	if err != nil {
		c.Fatal(err)
	}
	c.Log("OK")

	c.Log("Creating IPAM schema")
	err = ipam.CreateSchema(s.rootUrl, true)
	if err != nil {
		c.Fatal(err)
	}
	c.Log("OK")

	myLog(c, "Done with setup")

}

func myLog(c *check.C, args ...interface{}) {
	fmt.Println(args)
	c.Log(args)
}

// Test the integration with root and topology service
func (s *MySuite) TestIntegration(c *check.C) {
	myLog(c, "Entering TestIntegration()")

	dir, _ := os.Getwd()
	myLog(c, "In", dir)

	// 1. Start topology service
	myLog(c, "STARTING TOPOLOGY SERVICE")
	channelTop, err := topology.Run(s.rootUrl)
	if err != nil {
		c.Error(err)
	}
	msg := <-channelTop
	myLog(c, "Topology service said:", msg)

	// 2. Add some hosts to topology service and test.
	topoAddr := "http://" + s.config.Services["topology"].Common.Api.GetHostPort()
	client, err := common.NewRestClient(topoAddr)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Calling ", topoAddr)
	topIndex := &common.IndexResponse{}
	err = client.Get("/", &topIndex)
	if err != nil {
		c.Error(err)
	}

	c.Assert(topIndex.ServiceName, check.Equals, "topology")
	hostsRelUrl := topIndex.Links.FindByRel("host-list")
	hostsUrl := topoAddr + hostsRelUrl
	myLog(c, "Host list URL: ", hostsUrl)

	// Get list of hosts - should be empty for now.
	var hostList []common.HostMessage
	client.Get(hostsRelUrl, &hostList)
	myLog(c, "Host list: ", hostList)
	c.Assert(len(hostList), check.Equals, 0)
	newHostReq := common.HostMessage{Ip: "10.10.10.10", RomanaIp: "10.64.0.0/16", AgentPort: 9999, Name: "HOST1000"}

	newHostResp := common.HostMessage{}
	client.Post(hostsRelUrl, newHostReq, &newHostResp)
	myLog(c, "Response: ", newHostResp)
	c.Assert(newHostResp.Ip, check.Equals, "10.10.10.10")
	//	c.Assert(newHostResp.Id, check.Equals, "1")

	newHostReq = common.HostMessage{Ip: "10.10.10.11", RomanaIp: "10.65.0.0/16", AgentPort: 9999, Name: "HOST2000"}
	newHostResp = common.HostMessage{}
	client.Post(hostsRelUrl, newHostReq, &newHostResp)
	myLog(c, "Response: ", newHostResp)

	c.Assert(newHostResp.Ip, check.Equals, "10.10.10.11")
	c.Assert(newHostResp.Id, check.Equals, "2")

	var hostList2 []common.HostMessage
	client.Get(hostsRelUrl, &hostList2)
	myLog(c, "Host list: ", hostList2)

	c.Assert(len(hostList2), check.Equals, 2)

	// 3. Start tenant service
	myLog(c, "STARTING TENANT SERVICE")
	channelTen, err := tenant.Run(s.rootUrl)
	if err != nil {
		c.Error(err)
	}
	msg = <-channelTen
	myLog(c, "Tenant service said:", msg)
	tenantAddr := "http://" + s.config.Services["tenant"].Common.Api.GetHostPort()
	client, err = common.NewRestClient(tenantAddr)
	if err != nil {
		c.Error(err)
	}

	// 4. Add a tenant and a segment
	err = client.NewUrl(tenantAddr)
	if err != nil {
		c.Error(err)
	}

	// Add first tenant
	tIn := tenant.Tenant{Name: "t1"}
	tOut := tenant.Tenant{}
	err = client.Post("/tenants", tIn, &tOut)
	if err != nil {
		c.Error(err)
	}
	t1Id := tOut.Id
	myLog(c, "Tenant", tOut)

	// Add second tenant
	tIn = tenant.Tenant{Name: "t2"}
	tOut = tenant.Tenant{}
	err = client.Post("/tenants", tIn, &tOut)
	if err != nil {
		c.Error(err)
	}
	t2Id := tOut.Id
	myLog(c, "Tenant", tOut)

	// Find first tenant
	tOut2 := tenant.Tenant{}
	tenant1Path := fmt.Sprintf("/tenants/%d", t1Id)
	err = client.Get(tenant1Path, &tOut2)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Found", tOut2)

	// Add 2 segments to tenant 1
	sIn := tenant.Segment{Name: "s1", TenantId: t1Id}
	sOut := tenant.Segment{}
	err = client.Post(tenant1Path+"/segments", sIn, &sOut)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s1 to t1: ", sOut)
	sIn = tenant.Segment{Name: "s2", TenantId: t1Id}
	sOut = tenant.Segment{}
	err = client.Post(tenant1Path+"/segments", sIn, &sOut)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s2 to t1: ", sOut)

	// Add 2 segments to tenant 2
	tenant2Path := fmt.Sprintf("/tenants/%d", t2Id)

	sIn = tenant.Segment{Name: "s1", TenantId: t2Id}
	sOut = tenant.Segment{}
	err = client.Post(tenant2Path+"/segments", sIn, &sOut)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s1 to t2: ", sOut)

	sIn = tenant.Segment{Name: "s2", TenantId: t2Id}
	sOut = tenant.Segment{}
	err = client.Post(tenant2Path+"/segments", sIn, &sOut)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Added segment s2 to t2: ", sOut)

	// 4. Start IPAM service
	myLog(c, "STARTING IPAM SERVICE")
	channelIpam, err := ipam.Run(s.rootUrl)
	if err != nil {
		c.Error(err)
	}
	msg = <-channelIpam
	myLog(c, "IPAM service said:", msg)

	// Try to get an address
	ipamAddr := "http://" + s.config.Services["ipam"].Common.Api.GetHostPort()
	client, err = common.NewRestClient(ipamAddr)
	if err != nil {
		c.Error(err)
	}

	// Get first IP
	vmIn := ipam.Vm{Name: "vm1", TenantId: tOut.Id, SegmentId: sOut.Id, HostId: "2"}
	vmOut := ipam.Vm{}
	err = client.Post("/vms", vmIn, &vmOut)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Received:", vmOut)
	myLog(c, "IP:", vmOut.Ip)

	// Get second IP
	vmIn = ipam.Vm{Name: "vm2", TenantId: tOut.Id, SegmentId: sOut.Id, HostId: "2"}
	vmOut = ipam.Vm{}
	err = client.Post("/vms", vmIn, &vmOut)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Received:", vmOut)
	myLog(c, "IP:", vmOut.Ip)

	// Try legacy request
	vmOut = ipam.Vm{}
	legacyUrl := "/allocateIpByName?tenantName=t1&segmentName=s1&hostName=HOST2000&instanceName=bla"
	myLog(c, "Calling legacy URL", legacyUrl)

	err = client.Get(legacyUrl, &vmOut)

	if err != nil {
		myLog(c, "Error %s\n", err)
		c.Error(err)
	}
	myLog(c, "Legacy received:", vmOut)
	myLog(c, "Legacy IP:", vmOut.Ip)

	// 5. Start Agent service
	myLog(c, "STARTING Agent SERVICE")
	channelAgent, err := agent.Run(s.rootUrl)
	if err != nil {
		c.Error(err)
	}
	msg = <-channelAgent
	myLog(c, "Agent service said:", msg)

}
