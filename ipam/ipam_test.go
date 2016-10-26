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
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package ipam

import (
	"fmt"
	"github.com/go-check/check"
	"github.com/romana/core/common"
	"log"

	"net"
	"testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type MySuite struct {
	common.RomanaTestSuite
}

var _ = check.Suite(&MySuite{})

func (s *MySuite) TearDownSuite(c *check.C) {
	s.RomanaTestSuite.CleanUp()
}

func (s *MySuite) TestStore(c *check.C) {
	var err error

	store := ipamStore{}
	store.ServiceStore = &store

	storeConfig := make(map[string]interface{})
	storeConfig["type"] = "sqlite3"
	storeConfig["database"] = s.RomanaTestSuite.GetMockSqliteFile("ipam")
	err = store.SetConfig(storeConfig)
	c.Assert(err, check.IsNil)
	cidr := "10.0.0.0/8"
	ip, _, _ := net.ParseCIDR(cidr)

	dc := common.Datacenter{Cidr: cidr, IpVersion: 4, Prefix: common.IPv4ToInt(ip), PrefixBits: 8, PortBits: 8, TenantBits: 4, SegmentBits: 4}

	_, network, _ := net.ParseCIDR("10.1.0.0/16")
	hostIpInt := common.IPv4ToInt(network.IP)

	segmentBitShift := uint64(8)
	tenantBitShift := uint64(segmentBitShift + 4)
	upToEndpointIpInt := hostIpInt | (1 << tenantBitShift) | (1 << segmentBitShift)
	// 253
	// 127
	// 63
	// 31
	for _, stride := range []uint{0, 1, 2, 4} {
		//	for _, stride := range []uint{0} {
		err = store.CreateSchema(true)
		if err != nil {
			panic(err)
		}
		err = store.Connect()
		if err != nil {
			panic(err)
		}
		dc.EndpointSpaceBits = stride
		dc.EndpointBits = 8 - stride
		endpoint := &Endpoint{Id: 0, EffectiveNetworkID: 0, HostId: "X", SegmentID: "X", TenantID: "X"}
		i := uint(1)
		firstIp := ""
		var upperBound uint
		switch stride {
		case 0:
			upperBound = 253
		case 1:
			upperBound = 127
		case 2:
			upperBound = 64
		case 4:
			upperBound = 16
		}
		log.Printf("For %d/%d go until 1= %d", dc.EndpointBits, stride, upperBound)
		for i = 1; i <= uint(upperBound); i++ {
			endpoint.Id = 0
			msg := fmt.Sprintf("For stride %d, endpoint bits %d, try %d\n", stride, dc.EndpointBits, i)
			log.Println(msg)
			err = store.addEndpoint(endpoint, upToEndpointIpInt, dc)
			if err != nil {
				c.Error(fmt.Sprintf("Unexpected error on try %d: %v", i, err))
				c.FailNow()
			}
			log.Printf("%s: Got IP: %s (effective network ID %d)", msg, endpoint.Ip, endpoint.EffectiveNetworkID)
			if firstIp == "" {
				firstIp = endpoint.Ip
			}

		}
		// Here we have reached the end...
		endpoint.Id = 0
		err = store.addEndpoint(endpoint, upToEndpointIpInt, dc)
		if err == nil {
			c.Error(fmt.Sprintf("Expected error, but got %+v", endpoint))
			c.FailNow()
		}

		endpoint.Id = 0
		_, err = store.deleteEndpoint(firstIp)
		if err != nil {
			c.Error(fmt.Sprintf("Unexpected error on try %d: %v", i, err))
			c.FailNow()
		}
		endpoint.Id = 0
		err = store.addEndpoint(endpoint, upToEndpointIpInt, dc)
		if err != nil {
			c.Error(fmt.Sprintf("Unexpected error on try %d: %v", i, err))
			c.Fail()
		}
		c.Assert(endpoint.Ip, check.Equals, firstIp)
		if c.Failed() {
			return
		}

		endpoint.Id = 0
		err = store.addEndpoint(endpoint, upToEndpointIpInt, dc)
		if err == nil {
			c.Error(fmt.Sprintf("Expected error, but got %+v", endpoint))
			c.FailNow()
		}

	}
}
