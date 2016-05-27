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

package policy

import (
	"fmt"
	"log"
	//	"net/http"
	//	"net/url"
	"strconv"
	"strings"
	"testing"
	//	"time"
	"encoding/json"
	"github.com/go-check/check"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MySuite struct {
	serviceURL  string
	servicePort int
	kubeURL     string
	c           *check.C
}

var _ = check.Suite(&MySuite{})

// mockSvc is a Romana Service used in tests.
type mockSvc struct {
	mySuite *MySuite
	// To simulate tenant/segment database.
	// tenantCounter will provide tenant IDs
	tenantCounter uint64
	// Map of tenant ID to external ID
	tenants map[uint64]string
	// Map of External ID to tenant ID
	tenantsStr     map[string]uint64
	segmentCounter uint64
	segments       map[uint64]string
	segmentsStr    map[string]uint64
}

func (s *mockSvc) SetConfig(config common.ServiceConfig) error {
	return nil
}

func (s *mockSvc) Name() string {
	return common.ServiceRoot
}

func (s *mockSvc) Initialize() error {
	return nil
}

func (s *mockSvc) Routes() common.Routes {

	tenantGetRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants/1",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			return &tenant.Tenant{ID: 1, Name: "default", ExternalID: "default", RomanaNetworkID: 1}, nil
			},
		}


	segmentGetRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants/{tenantID}/segments/{segmentID}",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Printf("In segmentGetRoute\n\t%#v\n\t%#v", s.segments, s.segmentsStr)
			idStr := ctx.PathVariables["segmentID"]
			id, err := strconv.ParseUint(idStr, 10, 64)
			if err != nil {
				if s.segmentsStr[idStr] == 0 {
					return nil, common.NewError404("segment", idStr)
				}
				id = s.segmentsStr[idStr]
				return &tenant.Segment{ID: id, Name: idStr, ExternalID: idStr}, nil
			}
			if id < 1 || id > s.segmentCounter {
				return nil, common.NewError404("segment", idStr)
			}
			name := s.segments[s.segmentCounter]
			return &tenant.Segment{ID: id, Name: name, ExternalID: name}, nil
		},
	}

	policyConfigRoute := common.Route{
		Method:  "GET",
		Pattern: "/config/policy",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			json := `{
			          "common":{
						"api":{"host":"0.0.0.0","port":0}
					 },
			   	      "config":{"store":
			  			 {"type" : "sqlite3",  "database" : "/var/tmp/policy.sqlite3" }
			  		  }	 
			        }`
			return common.Raw{Body: json}, nil
		},
	}

	rootRoute := common.Route{
		Method:  "GET",
		Pattern: "/",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			json := `{"serviceName":"root",
			"Links":
			[
			{"Href":"/config/root","Rel":"root-config"},
			{"Href":"/config/ipam","Rel":"ipam-config"},
			{"Href":"/config/tenant","Rel":"tenant-config"},
			{"Href":"/config/topology","Rel":"topology-config"},
			{"Href":"/config/agent","Rel":"agent-config"},
			{"Href":"/config/policy","Rel":"policy-config"},
			{"Href":"/config/kubernetesListener","Rel":"kubernetesListener-config"},
			{"Href":"SERVICE_URL","Rel":"self"}
			], 
			"Services":
			[
			{"Name":"root","Links":[{"Href":"SERVICE_URL","Rel":"service"}]},
			{"Name":"ipam","Links":[{"Href":"SERVICE_URL","Rel":"service"}]},
			{"Name":"tenant","Links":[{"Href":"SERVICE_URL","Rel":"service"}]},
			{"Name":"topology","Links":[{"Href":"SERVICE_URL","Rel":"service"}]},
			{"Name":"agent","Links":[{"Href":"SERVICE_URL:PORT","Rel":"service"}]},
			{"Name":"policy","Links":[{"Href":"SERVICE_URL","Rel":"service"}]},
			{"Name":"kubernetesListener","Links":[{"Href":"SERVICE_URL","Rel":"service"}]}
			]
			}
			`
			retval := fmt.Sprintf(strings.Replace(json, "SERVICE_URL", s.mySuite.serviceURL, -1))
			//			log.Printf("Using %s->SERVICE_URL, replaced\n\t%swith\n\t%s", s.mySuite.serviceURL, json, retval)
			return common.Raw{Body: retval}, nil
		},
	}

	registerPortRoute := common.Route{
		Method:  "POST",
		Pattern: "/config/kubernetes-listener/port",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Printf("Received %#v", input)
			return "OK", nil
		},
	}

	routes := common.Routes{
		rootRoute,
		tenantAddRoute,
		tenantGetRoute,
		segmentGetRoute,
		segmentAddRoute,
		registerPortRoute,
		policyConfigRoute,
	}
	log.Printf("mockService: Set up routes: %#v", routes)
	return routes
}

type RomanaT struct {
	testing.T
}

func (s *MySuite) TestPolicy(c *check.C) {
	cfg := &common.ServiceConfig{Common: common.CommonConfig{Api: &common.Api{Port: 0, RestTimeoutMillis: 100}}}
	log.Printf("Test: Mock service config:\n\t%#v\n\t%#v\n", cfg.Common.Api, cfg.ServiceSpecific)
	svc := &mockSvc{mySuite: s}
	svc.tenants = make(map[uint64]string)
	svc.tenantsStr = make(map[string]uint64)
	svc.segments = make(map[uint64]string)
	svc.segmentsStr = make(map[string]uint64)
	svcInfo, err := common.InitializeService(svc, *cfg)
	if err != nil {
		panic(err)
	}
	msg := <-svcInfo.Channel
	log.Printf("Test: Mock service says %s\n", msg)
	s.serviceURL = fmt.Sprintf("http://%s", svcInfo.Address)
	log.Printf("Test: Mock service listens at %s\n", s.serviceURL)
	err = CreateSchema(s.serviceURL, true)
	if err != nil {
		panic(err)
	}
	log.Printf("Policy schema created.")
	svcInfo, err = Run(s.serviceURL, nil)
	if err != nil {
		panic(err)
	}

	msg = <-svcInfo.Channel
	fmt.Printf("Policy service listening %s on said: %s", svcInfo.Address, msg)

	clientConfig := common.GetDefaultRestClientConfig(s.serviceURL)
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		panic(err)
	}
	result := make(map[string]interface{})
	polURL := "http://" + svcInfo.Address + "/policies"
	policy := common.Policy{}
	err = json.Unmarshal([]byte(romanaPolicy), &policy)
	if err != nil {
		panic(err)
	}
	err = client.Post(polURL, policy, result)
}

const (
	romanaPolicy = `{"direction":"ingress","name":"pol1","datacenter":{"Id":0,"ip_version":0,
	"prefix":0,"prefix_bits":0,"port_bits":0,"tenant_bits":0,"segment_bits":0,
	"endpoint_bits":0,"endpoint_space_bits":0,"name":""},"applied_to":[{"tenant_id":1,
	"segment_id":1}],"peers":[{"tenant_id":1,"tenant_external_id":"default",
	"segment_id":2,"segment_external_id":"frontend"}],"rules":[{"protocol":"tcp","ports":[80]}]}`
)
