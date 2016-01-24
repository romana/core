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
	config          common.Config
	configFile      string
	rootUrl         string
	servicesStarted bool
}

var _ = check.Suite(&MySuite{})

func (s *MySuite) SetUpTest(c *check.C) {
	myLog(c, "Entering SetUP, services started: ", s.servicesStarted)
	if !s.servicesStarted {
		dir, _ := os.Getwd()
		myLog(c, "Entering setup in directory", dir)
		s.configFile = "../common/testdata/romana.sample.yaml"
		var err error
		s.config, err = common.ReadConfig(s.configFile)
		if err != nil {
			panic(err)
		}
		myLog(c, "Root configuration: ", s.config.Services["root"].Common.Api.GetHostPort())
		root.Run(s.configFile)
		s.rootUrl = "http://" + s.config.Services["root"].Common.Api.GetHostPort()
		myLog(c, "Root URL:", s.rootUrl)

		// Starting root service
		fmt.Println("Starting root service...")
		channelRoot, err := root.Run(s.configFile)
		if err != nil {
			c.Error(err)
		}
		msg := <-channelRoot
		myLog(c, "Root service said:", msg)

		myLog(c,"Creating topology schema")
		err = CreateSchema(s.rootUrl, true)
		myLog(c, "CreateSchema returned err: ", err, "which is of type", reflect.TypeOf(err), "let's compare it to", nil, ": err != nil: ", err != nil)
		if err != nil {
			c.Fatal(err)
		}
		s.servicesStarted = true
		myLog(c, "Done with setup")
	}
}

func myLog(c *check.C, args ...interface{}) {
	fmt.Println(args)
	c.Log(args)
}

// TestHostMarshaling tests marshaling/unmarshaling of Host
// structure to/from proper JSON.
func (s *MySuite) TestHostMarshaling(c *check.C) {
	host := Host{}
	host.Id = 1
	host.RomanaIp = "192.168.0.1/16"
	host.Ip = "10.1.1.1"
	host.Name = "host1"
	host.AgentPort = 9999
	m := common.ContentTypeMarshallers["application/json"]
	json, _ := m.Marshal(host)
	marshaledJsonStr := string(json)
	myLog(c, "Marshaled ", host, "to", marshaledJsonStr)
	expectedJsonStr := "{\"id\":1,\"name\":\"host1\",\"ip\":\"10.1.1.1\",\"romana_ip\":\"192.168.0.1/16\",\"agent_port\":9999}"
	c.Assert(marshaledJsonStr, check.Equals, expectedJsonStr)
	host2 := Host{}
	err := m.Unmarshal([]byte(expectedJsonStr), &host2)
	if err != nil {
		c.Error(err)
	}
	c.Assert(host2.Id, check.Equals, uint64(1))
	c.Assert(host2.Ip, check.Equals, "10.1.1.1")
	c.Assert(host2.RomanaIp, check.Equals, "192.168.0.1/16")
	c.Assert(host2.AgentPort, check.Equals, uint64(9999))
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
