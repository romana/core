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
	"encoding/json"
	"fmt"
	"github.com/go-check/check"
	"github.com/romana/core/common"
	"github.com/romana/core/root"

	"os"
	"reflect"
	"testing"
	"time"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type MySuite struct {
	common.RomanaTestSuite
	rootURL         string
	servicesStarted bool
}

var _ = check.Suite(&MySuite{})

func (s *MySuite) TearDownSuite(c *check.C) {
	s.RomanaTestSuite.CleanUp()
}

func (s *MySuite) SetUpTest(c *check.C) {

	myLog(c, "Entering SetUP, services started: ", s.servicesStarted)
	if !s.servicesStarted {
		dir, _ := os.Getwd()
		myLog(c, "Entering setup in directory", dir)
		var err error
		err = s.RomanaTestSuite.MockConfig(common.DefaultTestConfigFile)
		if err != nil {
			panic(err)
		}

		myLog(c, "Root configuration: ", s.RomanaTestSuite.Config.Services[common.ServiceNameRoot].Common.Api.GetHostPort())
		root.Run(s.RomanaTestSuite.ConfigFile)

		// Starting root service
		myLog(c, "Starting root service...")
		svcInfo, err := root.Run(s.RomanaTestSuite.ConfigFile)
		if err != nil {
			c.Error(err)
		}
		s.rootURL = "http://" + svcInfo.Address
		myLog(c, "Root URL:", s.rootURL)

		msg := <-svcInfo.Channel
		myLog(c, "Root service said:", msg)

		myLog(c, "Creating topology schema")
		topoSvc := &TopologySvc{}
		err = common.SimpleOverwriteSchema(topoSvc, s.rootURL, nil)
		myLog(c, "CreateSchema returned err: ", err, "which is of type", reflect.TypeOf(err), "let's compare it to", nil, ": err != nil: ", err != nil)
		if err != nil {
			c.Fatal(err)
		}
		s.servicesStarted = true
		myLog(c, "Done with setup")
	}
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

// TestHostMarshaling tests marshaling/unmarshaling of Host
// structure to/from proper JSON.
func (s *MySuite) TestHostMarshaling(c *check.C) {
	host := common.Host{}
	host.ID = 1
	host.RomanaIp = "192.168.0.1/16"
	host.Ip = "10.1.1.1"
	host.Name = "host1"
	host.AgentPort = 9999
	m := common.ContentTypeMarshallers["application/json"]
	json, _ := m.Marshal(host)
	marshaledJSONStr := string(json)
	myLog(c, "Marshaled ", host, "to", marshaledJSONStr)
	expectedJSONStr := "{\"id\":1,\"name\":\"host1\",\"ip\":\"10.1.1.1\",\"romana_ip\":\"192.168.0.1/16\",\"agent_port\":9999}"
	c.Assert(marshaledJSONStr, check.Equals, expectedJSONStr)
	host2 := common.Host{}
	err := m.Unmarshal([]byte(expectedJSONStr), &host2)
	if err != nil {
		c.Error(err)
	}
	c.Assert(host2.ID, check.Equals, uint64(1))
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
	topoSvc := &TopologySvc{}
	svcInfo, err := common.SimpleStartService(topoSvc, s.rootURL, nil)
	if err != nil {
		c.Error(err)
	}
	msg := <-svcInfo.Channel
	myLog(c, "Topology service said:", msg)
	addr := "http://" + svcInfo.Address
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(addr, nil))
	if err != nil {
		c.Error(err)
	}
	myLog(c, "Calling ", addr)

	topIndex := &common.IndexResponse{}
	err = client.Get("/", &topIndex)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}

	c.Assert(topIndex.ServiceName, check.Equals, "topology")
	hostsRelURL := topIndex.Links.FindByRel("host-list")
	hostsURL := addr + hostsRelURL
	myLog(c, "Host list URL: ", hostsURL)

	// Get list of hosts - should be empty for now.
	var hostList []common.Host
	err = client.Get(hostsRelURL, &hostList)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Host list: ", hostList)
	c.Assert(len(hostList), check.Equals, 0)
	newHostReq := common.Host{Ip: "10.10.10.10", AgentPort: 9999, Name: "host10", RomanaIp: "15.15.15.15"}

	newHostResp := common.Host{}
	err = client.Post(hostsRelURL, newHostReq, &newHostResp)
	if err != nil {
		c.Fatal(err)
	}
	myLog(c, "Response: ", newHostResp)
	myLog(c, "Waiting for....", time.Hour)
	//	time.Sleep(time.Hour)

	c.Assert(newHostResp.Ip, check.Equals, "10.10.10.10")

	newHostReq = common.Host{Ip: "10.10.10.11", AgentPort: 9999, Name: "host11", RomanaIp: "15.15.15.16"}
	newHostResp = common.Host{}
	err = client.Post(hostsRelURL, newHostReq, &newHostResp)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Response: ", newHostResp)

	err = client.Post(hostsRelURL, newHostReq, &newHostResp)
	if err == nil {
		c.Fatalf("Expected an error on adding a duplicate host...")
	}
	httpErr := err.(*common.HttpError)
	myLog(c, "Attempt to add duplicate host: %v", httpErr)
	c.Assert(httpErr.StatusCode, check.Equals, 409)

	newHostReqWithoutRomanaIP := common.Host{Ip: "10.10.10.12", AgentPort: 9999, Name: "host12"}
	newHostRespWithoutRomanaIP := common.Host{}
	err = client.Post(hostsRelURL, newHostReqWithoutRomanaIP, &newHostRespWithoutRomanaIP)
	if err != nil {
		c.Fatal(err)
	}
	myLog(c, "Response: ", newHostRespWithoutRomanaIP)

	c.Assert(newHostRespWithoutRomanaIP.Ip, check.Equals, "10.10.10.12")
	c.Assert(newHostRespWithoutRomanaIP.RomanaIp, check.Equals, "10.3.0.0/16")

	newHostReqWithoutRomanaIP = common.Host{Ip: "10.10.10.13", AgentPort: 9999, Name: "host13"}
	newHostRespWithoutRomanaIP = common.Host{}
	err = client.Post(hostsRelURL, newHostReqWithoutRomanaIP, &newHostRespWithoutRomanaIP)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Response: ", newHostRespWithoutRomanaIP)

	c.Assert(newHostRespWithoutRomanaIP.Ip, check.Equals, "10.10.10.13")
	c.Assert(newHostRespWithoutRomanaIP.RomanaIp, check.Equals, "10.4.0.0/16")

	// TODO: auto generation of romana cidr currently don't
	//       handle manually assigned one gracefully, thus tests
	//       to be added here once that support is added.

	var hostList2 []common.Host
	err = client.Get(hostsRelURL, &hostList2)
	if err != nil {
		c.Error(err)
		c.FailNow()
	}
	myLog(c, "Host list: ", hostList2)
	c.Assert(len(hostList2), check.Equals, 4)
}
