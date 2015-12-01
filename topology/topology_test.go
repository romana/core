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
package topology

import (
	"fmt"
	"github.com/go-check/check"
	"github.com/romana/core/common"
	"github.com/romana/core/root"
	"reflect"

	"os"

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
	s.configFile = "../common/testdata/pani.sample.yaml"
	var err error
	s.config, err = common.ReadConfig(s.configFile)
	if err != nil {
		panic(err)
	}
	c.Log("Root configuration: ", s.config.Services["root"].Common.Api.GetHostPort())
	root.Run(s.configFile)
	s.rootUrl = "http://" + s.config.Services["root"].Common.Api.GetHostPort()
	c.Log("Root URL:", s.rootUrl)

	// Starting root service
	fmt.Println("Starting root service...")
	channelRoot, err := root.Run(s.configFile)
	if err != nil {
		c.Error(err)
	}
	msg := <-channelRoot
	c.Log("Root service said:", msg)

	c.Log("Creating topology schema")
	err = CreateSchema(s.rootUrl, true)
	myLog(c, "CreateSchema returned err: ", err, "which is of type", reflect.TypeOf(err), "let's compare it to", nil, ": err != nil: ", err != nil)
	if err != nil {
		c.Fatal(err)
	}

	myLog(c, "Done with setup")
}

func myLog(c *check.C, args ...interface{}) {
	fmt.Println(args)
	c.Log(args)
}

// Test the topology service
func (s *MySuite) TestTopology(c *check.C) {
	myLog(c, "Entering TestTopology()")

	dir, _ := os.Getwd()
	myLog(c, "In", dir)
	myLog(c, "Starting topology service")

	channelTop, err := Run(s.rootUrl)
	if err != nil {
		c.Error(err)
	}
	msg := <-channelTop
	myLog(c, "Topology service said:", msg)
	addr := "http://" + s.config.Services["topology"].Common.Api.GetHostPort()
	client, err := common.NewRestClient(addr)
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Calling ", addr)

	topIndex := &common.IndexResponse{}
	err = client.Get("/", &topIndex)
	if err != nil {
		c.Error(err)
	}
	
	c.Assert(topIndex.ServiceName, check.Equals, "topology")
	hostsRelUrl := topIndex.Links.FindByRel("host-list")
	hostsUrl := addr + hostsRelUrl
	myLog(c, "Host list URL: ", hostsUrl)

	// Get list of hosts - should be empty for now.
	var hostList []Host
	client.Get(hostsRelUrl, &hostList)
	myLog(c, "Host list: ", hostList)
	c.Assert(len(hostList), check.Equals, 0)
	newHostReq := common.HostMessage{Ip: "10.10.10.10", AgentPort: 9999, Name: "host10"}

	newHostResp := common.HostMessage{}
	client.Post(hostsRelUrl, newHostReq, &newHostResp)
	myLog(c, "Response: ", newHostResp)
	c.Assert(newHostResp.Ip, check.Equals, "10.10.10.10")
	c.Assert(newHostResp.Id, check.Equals, "1")

	newHostReq = common.HostMessage{Ip: "10.10.10.11", AgentPort: 9999, Name: "host11"}
	newHostResp = common.HostMessage{}
	client.Post(hostsRelUrl, newHostReq, &newHostResp)
	myLog(c, "Response: ", newHostResp)

	c.Assert(newHostResp.Ip, check.Equals, "10.10.10.11")
	c.Assert(newHostResp.Id, check.Equals, "2")

	var hostList2 []Host
	client.Get(hostsRelUrl, &hostList2)
	myLog(c, "Host list: ", hostList2)
	c.Assert(len(hostList2), check.Equals, 2)

}
