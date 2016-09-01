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
	"encoding/json"
	"fmt"
	"github.com/go-check/check"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"log"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MySuite struct {
	serviceURL  string
	servicePort uint64
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
			return &tenant.Tenant{ID: 1, Name: "default", ExternalID: "default", NetworkID: 1}, nil
		},
	}

	segmentGetRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants/1/segments/{id}",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			idInt, err := strconv.ParseUint(ctx.PathVariables["id"], 10, 64)
			if err != nil {
				return nil, err
			}
			return &tenant.Segment{ID: idInt, Name: "backend", ExternalID: "backend"}, nil
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

			//			json = `{
			//			          "common":{
			//						"api":{"host":"0.0.0.0","port":0}
			//					 },
			//			   	      "config":{"store":
			//			  			 {"type" : "mysql",  "database" : "policy", "host" : "127.0.0.1", "port" : "8889", "username" : "root", "password" : "root" }
			//			  		  }
			//			        }`
			return common.Raw{Body: json}, nil
		},
	}

	// Simulate agent
	agentAddPolicyRoute := common.Route{
		Method:  "POST",
		Pattern: "/policies",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Printf("Agent received policy: %v", input)
			policyDoc := input.(*common.Policy)
			log.Printf("Agent received policy: %s", policyDoc.Name)
			if policyDoc.Datacenter.TenantBits == 0 {
				return nil, common.NewError400("Datacenter information invalid.")
			}
			return nil, nil
		},
		MakeMessage: func() interface{} { return &common.Policy{} },
	}

	agentDeletePolicyRoute := common.Route{
		Method:  "DELETE",
		Pattern: "/policies",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Printf("Agent received policy: %v", input)
			policyDoc := input.(*common.Policy)
			log.Printf("Agent received policy: %s", policyDoc.Name)
			if policyDoc.Datacenter.TenantBits == 0 {
				return nil, common.NewError400("Datacenter information invalid.")
			}
			return nil, nil
		},
		MakeMessage: func() interface{} { return &common.Policy{} },
	}

	// This simulates both root's and topology's index response
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
			{"Href":"/datacenter","Rel":"datacenter"},
			{"Href":"/hosts","Rel":"host-list"},
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

	dcRoute := common.Route{
		Method:  "GET",
		Pattern: "/datacenter",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			json := `
			{"id":0,
			"ip_version":4,
			"cidr":"10.0.0.0/8",
			"prefix_bits":8,
			"port_bits":8,
			"tenant_bits":4,
			"segment_bits":4,
			"endpoint_bits":8,
			"endpoint_space_bits":0,
			"name":"main"}
			`
			return common.Raw{Body: json}, nil
		},
	}

	hostsRoute := common.Route{
		Method:  "GET",
		Pattern: "/hosts",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			hosts := make([]common.Host, 1)
			hosts[0] = common.Host{Ip: "127.0.0.1", AgentPort: s.mySuite.servicePort}
			return hosts, nil
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
		tenantGetRoute,
		segmentGetRoute,
		registerPortRoute,
		policyConfigRoute,
		dcRoute,
		hostsRoute,
		agentAddPolicyRoute,
		agentDeletePolicyRoute,
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
		c.Fatal(err)
	}
	msg := <-svcInfo.Channel
	log.Printf("Test: Mock service says %s; listening on %s\n", msg, svcInfo.Address)
	addrComponents := strings.Split(svcInfo.Address, ":")
	portStr := addrComponents[len(addrComponents)-1]
	s.servicePort, err = strconv.ParseUint(portStr, 10, 64)
	if err != nil {
		c.Fatal(err)
	}
	s.serviceURL = fmt.Sprintf("http://%s", svcInfo.Address)
	log.Printf("Test: Mock service listens at %s\n", s.serviceURL)
	err = CreateSchema(s.serviceURL, true)

	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Policy schema created.")
	svcInfo, err = Run(s.serviceURL, nil)
	if err != nil {
		c.Fatal(err)
	}

	msg = <-svcInfo.Channel
	fmt.Printf("Policy service listening %s on said: %s", svcInfo.Address, msg)

	clientConfig := common.GetDefaultRestClientConfig(s.serviceURL)
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		c.Fatal(err)
	}
	polURL := "http://" + svcInfo.Address + "/policies"

	log.Println("1. Add policy pol1")
	policyIn := common.Policy{}
	err = json.Unmarshal([]byte(romanaPolicy1), &policyIn)
	if err != nil {
		c.Fatal(err)
	}
	policyOut := common.Policy{}
	err = client.Post(polURL, policyIn, &policyOut)
	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Added policy result: %s", policyOut)
	c.Assert(policyOut.Name, check.Equals, "pol1")
	c.Assert(*policyOut.ID, check.Equals, uint64(1))
	c.Assert(len(policyOut.AppliedTo), check.Equals, len(policyIn.AppliedTo))
	c.Assert(len(policyOut.Peers), check.Equals, len(policyIn.Peers))
	c.Assert(client.GetStatusCode(), check.Equals, 200)

	pol1ExternalID := policyIn.ExternalID
	policyIn.ExternalID = "asdfghjkl"
	policyIn.ID = policyOut.ID
	log.Printf("2. Add policy again with different External ID %s but same ID %d", policyIn.ExternalID, policyIn.ID)
	err = client.Post(polURL, policyIn, &policyOut)
	c.Assert(err.(common.HttpError).StatusCode, check.Equals, http.StatusConflict)
	log.Printf("2. Result: %+v", policyOut)

	log.Println("3. Add policy again")
	policyIn.ExternalID = pol1ExternalID
	policyIn.ID = nil
	err = client.Post(polURL, policyIn, &policyOut)
	c.Assert(err.(common.HttpError).StatusCode, check.Equals, http.StatusConflict)
	log.Printf("3. Result: %+v", policyOut)

	log.Println("4. Add policy pol2")
	err = json.Unmarshal([]byte(romanaPolicy2), &policyIn)
	if err != nil {
		c.Fatal(err)
	}
	err = client.Post(polURL, policyIn, &policyOut)
	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Added policy result: %s", policyOut)
	c.Assert(client.GetStatusCode(), check.Equals, 200)
	c.Assert(policyOut.Name, check.Equals, "pol2")

	log.Println("5. Add default policy")
	one := uint64(1)
	defPol := common.Policy{
		Direction: common.PolicyDirectionIngress,
		Name:      "default",
		AppliedTo: []common.Endpoint{{TenantNetworkID: &one}},
		Peers:     []common.Endpoint{{Peer: common.Wildcard}},
		Rules:     []common.Rule{{Protocol: common.Wildcard}},
	}
	err = client.Post(polURL, defPol, &policyOut)
	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Added policy result: %s", policyOut)
	c.Assert(client.GetStatusCode(), check.Equals, 200)
	c.Assert(policyOut.Name, check.Equals, "default")

	log.Println("6. Test list policies - should have 3.")
	var policies []common.Policy
	err = client.Get(polURL, &policies)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(len(policies), check.Equals, 3)
	c.Assert(client.GetStatusCode(), check.Equals, 200)
	c.Assert(policies[0].Name, check.Equals, "pol1")
	c.Assert(policies[1].Name, check.Equals, "pol2")
	c.Assert(policies[2].Name, check.Equals, "default")

	log.Println("7. Test get policy.")
	policyGet := common.Policy{}
	err = client.Get(polURL+"/1", &policyGet)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(policyGet.Name, check.Equals, policies[0].Name)
	c.Assert(client.GetStatusCode(), check.Equals, 200)

	log.Println("8. Test delete by ID - delete pol1")
	policyOut = common.Policy{}
	err = client.Delete(polURL+"/1", nil, &policyOut)
	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Deleted policy result: %s", policyOut)
	c.Assert(policyOut.Name, check.Equals, "pol1")
	c.Assert(*policyOut.ID, check.Equals, uint64(1))
	c.Assert(client.GetStatusCode(), check.Equals, 200)

	log.Println("9. Test list policies - should have 2 now - pol2 and default.")
	err = client.Get(polURL, &policies)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(len(policies), check.Equals, 2)
	c.Assert(policies[0].Name, check.Equals, "pol2")
	c.Assert(policies[1].Name, check.Equals, "default")
	c.Assert(client.GetStatusCode(), check.Equals, 200)

	log.Println("10. Test delete by ExternalID - delete policy 2")
	err = json.Unmarshal([]byte(romanaPolicy2), &policyIn)
	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Unmarshaled %s to %v", romanaPolicy2, policyIn)
	policyOut = common.Policy{}
	err = client.Delete(polURL, policyIn, &policyOut)
	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Deleted policy result: %s", policyOut)
	c.Assert(client.GetStatusCode(), check.Equals, 200)
	c.Assert(policyOut.Name, check.Equals, policyIn.Name)

	log.Println("10. Test list policies - should have 1 now - only default")
	err = client.Get(polURL, &policies)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(client.GetStatusCode(), check.Equals, 200)
	c.Assert(len(policies), check.Equals, 1)
	c.Assert(policies[0].Name, check.Equals, "default")

	log.Println("11. Test find by name policies - should find it")
	findURL := "http://" + svcInfo.Address + "/find/policies"
	err = client.Get(findURL+"/default", &policyOut)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(policyOut.Name, check.Equals, "default")

	log.Println("12. Test find by name policies with non-existent policy - should NOT find it")
	err = client.Get(findURL+"/blabla", &policyOut)
	httpErr := err.(common.HttpError)
	c.Assert(client.GetStatusCode(), check.Equals, http.StatusNotFound)
	c.Assert(httpErr.ResourceType, check.Equals, "policy")
	c.Assert(httpErr.StatusCode, check.Equals, http.StatusNotFound)
	c.Assert(httpErr.ResourceID, check.Equals, "blabla")
	log.Printf("%v", err)

	log.Println("13. Test delete by ExternalID - delete default policy")
	policyOut = common.Policy{}
	err = client.Delete(polURL, defPol, &policyOut)

	if err != nil {
		c.Fatal(err)
	}
	log.Printf("Deleted policy result: %s", policyOut)
	c.Assert(policyOut.Name, check.Equals, defPol.Name)
	c.Assert(client.GetStatusCode(), check.Equals, 200)

	log.Println("14. Test list policies - should have 0 now")
	err = client.Get(polURL, &policies)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(len(policies), check.Equals, 0)

	log.Println("15. Test delete by ExternalID - delete default policy - should be Not Found error now")
	policyOut = common.Policy{}
	err = client.Delete(polURL, defPol, &policyOut)
	if err == nil {
		panic("Expected error")
	}
	httpErr = err.(common.HttpError)
	c.Assert(client.GetStatusCode(), check.Equals, http.StatusNotFound)
	c.Assert(httpErr.ResourceType, check.Equals, "policy")
	c.Assert(httpErr.StatusCode, check.Equals, http.StatusNotFound)
	c.Assert(httpErr.ResourceID, check.Equals, "default")
	log.Printf("%v", err)

}

const (
	romanaPolicy1 = `{
	"direction":"ingress",
	"external_id" : "pol1ExternalID",
	"name":"pol1",
	"datacenter":{	"id":0 },
	"applied_to":[
					{
					 "tenant_id":1,
					 "segment_id":1
					 }
				  ],
  	"peers":[
     {
      "tenant_id":1,
      "tenant_external_id":"default",
	  "segment_id":2,
	  "segment_external_id":"frontend"
	  }
	],
  	"rules":[
            {
            "protocol":"tcp",
            "ports":[80]
            }
      ]
   }`

	romanaPolicy2 = `{
	"direction":"ingress",
	"name":"pol2",
	"datacenter":{	"id":0 },
	"applied_to":[
					{
					 "tenant_id":1,
					 "segment_id":1
					 }
				  ],
  	"peers":[
     {
      "tenant_id":1,
      "tenant_external_id":"default",
	  "segment_id":2,
	  "segment_external_id":"frontend"
	  }
	],
  	"rules":[
            {
            "protocol":"tcp",
            "ports":[80]
            }
      ]
   }`
)
