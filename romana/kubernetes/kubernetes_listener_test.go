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

package kubernetes

import (
	"encoding/json"
	"fmt"
	"github.com/go-check/check"
	"github.com/golang/glog"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"net/http"
	"net/url"

	"strconv"
	"strings"
	"testing"
	"time"
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

type kubeSimulator struct {
	mockSvc *mockSvc
}

// ServeHTTP is a handler that will be used to simulate Kubernetes
func (ks *kubeSimulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//	w.Header().Set("Connection", "Keep-Alive")
	//	w.Header().Set("Transfer-Encoding", "chunked")
	glog.Infoln("Test: Entered kubeSimulator ServeHTTP()")
	// flusher, _ := w.(http.Flusher)

	//	flusher, _ := w.(http.Flusher)
	reqURI, _ := url.Parse(r.RequestURI)
	path := fmt.Sprintf("%s?%s", reqURI.Path, reqURI.RawQuery)
	glog.Infof("KubeSimulator: At %s", path)

	var ns Event
	err := json.Unmarshal([]byte(addNamespace1), &ns)
	if err != nil {
		glog.Infof("KubeSimulator: At %s: failed to unmarshall kube event %s", path, err)
		return
	}

	var pol Event
	err = json.Unmarshal([]byte(addPolicy1), &pol)
	if err != nil {
		glog.Infof("KubeSimulator: At %s: failed to unmarshall kube event %sl", path, err)
		return
	}

	if path == "/api/v1/namespaces/?watch=true" {
		glog.Infof("KubeSimulator: At %s: Sending namespace event %s", path, addNamespace1)
		//		fmt.Fprintf(w, addNamespace1)
		enc := json.NewEncoder(w)
		for {
			err = enc.Encode(ns)
			if err != nil {
				glog.Infof("KubeSimulator: At %s: failed to encode namespace event %s", path, err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	if strings.HasPrefix(path, "/apis/extensions/v1beta1/namespaces/") && strings.HasSuffix(path, "/networkpolicies?") {
		glog.Infof("KubeSimulator: At %s", path)
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("{ \"metadata\" : { \"resourceVersion\" : \"1\" } }"))
		flusher.Flush()

		return
	}

	m := make(map[string]string)
	m["x"] = "y"
	if strings.HasPrefix(path, "/apis/extensions/v1beta1/namespaces/") && strings.HasSuffix(path, "/networkpolicies?watch=true&resourceVersion=1") {
		glog.Infof("KubeSimulator: At %s", path)
		uriArr := strings.Split(path, "/")
		if len(uriArr) != 7 {
			glog.Infof("KubeSimulator: At %s, exiting expected 8 parts in url, got %d", path, len(uriArr))
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(fmt.Sprintf("{\"error\" : \"Not found: %s (expected 9, got %d parts of the URL: %v)\"}", path, len(uriArr), uriArr)))
			return
		}

		for {
			glog.Infof("KubeSimulator: At %s: have %d tenants", path, len(ks.mockSvc.tenants))
			// Wait until sentNamespaceEvent is true
			if len(ks.mockSvc.tenants) == 1 {
				glog.Infof("KubeSimulator: At %s: tenants[1]: %+v", path, *ks.mockSvc.tenants[1])
				break
			}

			flusher, _ := w.(http.Flusher)
			w.Write([]byte("{}"))
			flusher.Flush()

			if err != nil {
				glog.Infof("KubeSimulator: At %s: failed to encode empty event %s", path, err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}

		enc := json.NewEncoder(w)
		for {
			err = enc.Encode(pol)
			if err != nil {
				glog.Infof("KubeSimulator: At %s: failed to encode policy event %s", path, err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(fmt.Sprintf("Not found: %s", path)))
	return
}

// mockSvc is a Romana Service used in tests.
type mockSvc struct {
	mySuite *MySuite
	// To simulate tenant/segment database.
	// tenantCounter will provide tenant IDs
	tenantCounter uint64
	// Map of tenant ID Tenant
	tenants map[uint64]*tenant.Tenant

	segmentCounter uint64

	segments map[uint64]*tenant.Segment
	policies []common.Policy
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
	addPolicyRoute := common.Route{
		Method:  "POST",
		Pattern: "/policies",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("MockService: Entering POST /policies\n")
			j, _ := json.Marshal(input)
			glog.Infof("Mock policy received: %T %s", input, j)
			switch input := input.(type) {
			case *common.Policy:
				for _, p := range s.policies {
					if p.Name == input.Name {
						return input, common.NewErrorConflict(fmt.Sprintf("Policy with name %s already exists", input.Name))
					}
				}
				s.policies = append(s.policies, *input)
				return input, nil
			default:
				panic(common.NewError("Expected common.Policy, got %+v", input))
			}
		},
		MakeMessage: func() interface{} { return &common.Policy{} },
	}

	deletePolicyRoute := common.Route{
		Method:  "DELETE",
		Pattern: "/policies/{policyID}",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			idStr := ctx.PathVariables["policyID"]
			glog.Infof("MockService: Entering DELETE /policies/%s\n", idStr)
			id, err := strconv.ParseUint(idStr, 10, 64)
			if err != nil {
				return nil, common.NewError400(fmt.Sprintf("Bad ID %s", idStr))
			}
			delete := func(i int, a []common.Policy) []common.Policy {
				return append(a[:i], a[i+1:]...)
			}
			var ret *common.Policy
			for n, _ := range s.policies {
				glog.Infof("DEBUG delete policy by id, comparing %d and %d", s.policies[n].ID, id)
				if s.policies[n].ID == id {
					ret = &s.policies[n]
					s.policies = delete(n, s.policies)
					break
				}
			}

			if ret == nil {
				return nil, common.NewError404("policies", idStr)
			}
			return ret, nil
		},
	}

	policyGetAll := common.Route{
		Method:  "GET",
		Pattern: "/policies",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("MockService: Entering GET /policies\n")

			return s.policies, nil
		},
	}

	findLastTenantRoute := common.Route{
		Method:  "GET",
		Pattern: "/findLast/tenants",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("MockService: Entering GET /findLast/tenants with %+v\n", ctx.QueryVariables)
			name := ctx.QueryVariables["name"][0]
			var found *tenant.Tenant
			for _, v := range s.tenants {
				if name == v.Name {
					found = v
				}
			}
			if found == nil {
				return nil, common.NewError404("tenant", fmt.Sprintf("name=%s", name))
			}
			return found, nil
		},
		MakeMessage: nil,
	}

	findExactlyOneSegmentRoute := common.Route{
		Method:  "GET",
		Pattern: "/findExactlyOne/segments",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("MockService: Entering GET /findExactlyOne/segments with %+v\n", ctx.QueryVariables)
			name := ctx.QueryVariables["name"][0]
			var found *tenant.Segment
			for _, v := range s.segments {
				if name == v.Name {
					if found != nil {
						return nil, common.NewError500(fmt.Sprintf("Multiple results found for %s", name))
					}
					found = v
				}
			}
			if found == nil {
				return nil, common.NewError404("segment", fmt.Sprintf("name=%s", name))
			}
			return found, nil
		},
		MakeMessage: nil,
	}

	kubeListenerConfigRoute := common.Route{
		Method:  "GET",
		Pattern: "/config/kubernetesListener",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("MockService: Entering GET /config/kubernetesListener\n")
			json := `{"common":{"api":{"host":"0.0.0.0","port":9606}},
			"config":{"kubernetes_url":"http://localhost",
			"segment_label_name":"tier",
			"namespace_notification_path: "/api/v1/namespaces",
			"policy_notification_path_prefix : "apis/extensions/v1beta1/namespaces",
			"policy_notification_path_postfix : "networkpolicies",
      		}}`
			return common.Raw{Body: json}, nil
		},
	}

	tenantAddRoute := common.Route{
		Method:  "POST",
		Pattern: "/tenants",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infoln("MockService: Entering POST /tenants with %+v\n", input)
			newTenant := input.(*tenant.Tenant)
			for _, v := range s.tenants {
				if v.ExternalID == newTenant.ExternalID {
					return nil, common.NewErrorConflict(newTenant)
				}
			}
			s.tenantCounter++
			newTenant.ID = s.tenantCounter
			s.tenants[newTenant.ID] = newTenant
			str := ""
			for k, v := range s.tenants {
				str += fmt.Sprintf("\t%d => %+v\n", k, v)
			}
			glog.Infof("MockService: Have tenants: %s", str)
			return newTenant, nil
		},
		MakeMessage: func() interface{} { return &tenant.Tenant{} },
	}

	tenantGetRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants/{tenantID}",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			idStr := ctx.PathVariables["tenantID"]
			glog.Infof("MockService: Entering GET /tenants/%s\n", idStr)
			id, err := strconv.ParseUint(idStr, 10, 64)
			if err != nil {
				return nil, common.NewError400(fmt.Sprintf("Bad ID %s", idStr))
			}
			tenant := s.tenants[id]
			if tenant == nil {
				return nil, common.NewError404("tenant", idStr)
			}
			return tenant, nil
		},
	}

	tenantGetAllRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("MockService: Entering GET /tenants")
			var tr []tenant.Tenant
			for tk, _ := range s.tenants {
				tr = append(tr, *s.tenants[tk])
			}

			return tr, nil
		},
	}

	segmentAddRoute := common.Route{
		Method: "POST",
		// For the purpose of this test, we are going to ignore tenantID and pretend
		// it's the correct one.
		Pattern: "/tenants/{tenantID}/segments",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			tenantIDStr := ctx.PathVariables["tenantID"]
			glog.Infoln("MockService: Entering POST /tenants/%s/segment\n", tenantIDStr)
			newSegment := input.(*tenant.Segment)
			tenantID, _ := strconv.Atoi(tenantIDStr)
			newSegment.TenantID = uint64(tenantID)
			for _, v := range s.segments {
				if newSegment.ExternalID == v.ExternalID && newSegment.Name == v.Name {
					return nil, common.NewErrorConflict(newSegment)
				}
			}

			s.segmentCounter++
			newSegment.ID = s.segmentCounter
			s.segments[s.segmentCounter] = newSegment
			str := ""
			for k, v := range s.segments {
				str += fmt.Sprintf("\t%d => %+v\n", k, v)
			}
			glog.Infof("MockService: Have segments: %s", str)
			return newSegment, nil
		},
		MakeMessage: func() interface{} { return &tenant.Segment{} },
	}

	segmentGetAllRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants/{tenantID}/segments",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			var sr []tenant.Segment
			tenantIDStr := ctx.PathVariables["tenantID"]
			id, err := strconv.ParseUint(tenantIDStr, 10, 64)
			if err != nil {
				return nil, common.NewError400(fmt.Sprintf("Bad ID %s", tenantIDStr))
			}
			for sn, sv := range s.segments {
				if sv.TenantID == id {
					sr = append(sr, *s.segments[sn])
				}
			}

			return sr, nil
		},
	}

	segmentGetRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants/{tenantID}/segments/{segmentID}",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			tenantIDStr := ctx.PathVariables["tenantID"]
			segmentIDStr := ctx.PathVariables["segmentID"]
			glog.Infof("MockService: Entering GET /tenants/%s/segment/%s\n", tenantIDStr, segmentIDStr)
			segmentID, err := strconv.ParseUint(segmentIDStr, 10, 64)
			if err != nil {
				return nil, common.NewError400(fmt.Sprintf("Bad ID %s", segmentIDStr))
			}
			segment := s.segments[segmentID]
			if segment == nil {
				return nil, common.NewError404("segment", segmentIDStr)
			}
			return segment, nil
		},
	}

	rootRoute := common.Route{
		Method:  "GET",
		Pattern: "/",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("MockService: Entering GET /\n")
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
			//			glog.Infof("Using %s->SERVICE_URL, replaced\n\t%swith\n\t%s", s.mySuite.serviceURL, json, retval)
			return common.Raw{Body: retval}, nil
		},
	}

	registerPortRoute := common.Route{
		Method:  "POST",
		Pattern: "/config/kubernetes-listener/port",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			glog.Infof("Received %+v", input)
			return "OK", nil
		},
	}

	routes := common.Routes{
		addPolicyRoute,
		deletePolicyRoute,
		policyGetAll,
		rootRoute,
		tenantAddRoute,
		tenantGetRoute,
		tenantGetAllRoute,
		segmentGetRoute,
		segmentGetAllRoute,
		segmentAddRoute,
		kubeListenerConfigRoute,
		registerPortRoute,
		findExactlyOneSegmentRoute,
		findLastTenantRoute,
	}
	glog.Infof("mockService: Set up routes: %+v", routes)
	return routes
}

func (s *MySuite) getKubeListenerServiceConfig() *common.ServiceConfig {
	url, _ := url.Parse(s.serviceURL)
	hostPort := strings.Split(url.Host, ":")
	port, _ := strconv.ParseUint(hostPort[1], 10, 64)
	api := &common.Api{Host: "localhost", Port: port, RootServiceUrl: s.serviceURL}
	commonConfig := common.CommonConfig{Api: api}
	kubeListenerConfig := make(map[string]interface{})
	kubeListenerConfig["kubernetes_url"] = s.kubeURL
	kubeListenerConfig["namespace_notification_path"] = "/api/v1/namespaces"
	kubeListenerConfig["policy_notification_path_prefix"] = "apis/extensions/v1beta1/namespaces"
	kubeListenerConfig["policy_notification_path_postfix"] = "networkpolicies"
	kubeListenerConfig["segment_label_name"] = "tier"

	svcConfig := common.ServiceConfig{Common: commonConfig, ServiceSpecific: kubeListenerConfig}
	glog.Infof("Test: Returning KubernetesListener config %+v", svcConfig.ServiceSpecific)
	return &svcConfig

}

type RomanaT struct {
	testing.T
}

func (s *MySuite) startListener() error {
	clientConfig := common.GetDefaultRestClientConfig(s.serviceURL)
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		return err
	}
	kubeListener := &kubeListener{}
	kubeListener.restClient = client
	config := s.getKubeListenerServiceConfig()

	_, err = common.InitializeService(kubeListener, *config)
	if err != nil {
		return err
	}

	// DEBUG </
	tc := PTranslator.GetClient()
	if tc == nil {
		glog.Error("DEBUG Translator has nil client before Init")
	}

	PTranslator.Init(client, kubeListener.segmentLabelName)
	tc = PTranslator.GetClient()
	if tc == nil {
		glog.Fatal("DEBUG Translator has nil client after Init")
	}

	// DEBUG />

	return nil
}

func (s *MySuite) TestListener(c *check.C) {
	var err error
	cfg := &common.ServiceConfig{Common: common.CommonConfig{Api: &common.Api{Port: 0, RestTimeoutMillis: 100}}}
	glog.Infof("Test: Mock service config:\n\t%+v\n\t%+v\n", cfg.Common.Api, cfg.ServiceSpecific)
	svc := &mockSvc{mySuite: s}
	svc.tenants = make(map[uint64]*tenant.Tenant)
	svc.segments = make(map[uint64]*tenant.Segment)
	svc.policies = make([]common.Policy, 0)
	svc.policies = append(svc.policies, makeTestPolicy2())
	svcInfo, err := common.InitializeService(svc, *cfg)
	if err != nil {
		c.Error(err)
	}
	msg := <-svcInfo.Channel
	glog.Infof("Test: Mock service says %s\n", msg)
	s.serviceURL = fmt.Sprintf("http://%s", svcInfo.Address)
	glog.Infof("Test: Mock service listens at %s\n", s.serviceURL)

	// Start Kubernetes simulator
	svr := &http.Server{}
	svr.Handler = &kubeSimulator{mockSvc: svc}
	glog.Infof("TestListener: Calling ListenAndServe(%p)", svr)
	svcInfo, err = common.ListenAndServe(svr)
	if err != nil {
		c.Error(err)
	}
	msg = <-svcInfo.Channel
	glog.Infof("TestListener: Kubernetes said %s", msg)
	s.kubeURL = fmt.Sprintf("http://%s", svcInfo.Address)
	glog.Infof("Test: Kubernetes listening on %s (%s)", s.kubeURL, svcInfo.Address)

	// Start listener
	err = s.startListener()
	if err != nil {
		c.Error(err)
	}
	glog.Infof("Test: KubeListener started\n")
	time.Sleep(5 * time.Second)
	glog.Infof("Policies: %+v\n", svc.policies)
	c.Assert(len(svc.policies), check.Equals, 2)
	c.Assert(svc.policies[0].Name, check.Equals, "ns0")
	c.Assert(svc.policies[1].Name, check.Equals, "kube.default.pol1")
}

func makeTestPolicy2() common.Policy {
	TestPolicy2 := common.Policy{
		Description: "Predefined test policy to test listener sync",
		Direction:   "ingress",
		Name:        "kube.default.pol2",
		ID:          999,
		AppliedTo: []common.Endpoint{
			common.Endpoint{
				Dest: "host",
			},
		},
		Peers: []common.Endpoint{
			common.Endpoint{
				Peer: "local",
			},
		},
		Rules: []common.Rule{
			common.Rule{
				Ports:    []uint{67},
				Protocol: "UPD",
			},
		},
	}
	return TestPolicy2
}

const (
	addPolicy1 = `{
		"type":"ADDED",
		"object":
			{
				"apiVersion":"romana.io/demo/v1",
				"kind":"NetworkPolicy",
				"metadata":
					{
						"name":"pol1",
						"namespace":"default",
						"selfLink":"/apis/extensions/v1beta1/namespaces/default/networkpolicies/pol1",
						"uid":"d7036130-e119-11e5-aab8-0213e1312dc5",
						"resourceVersion":"119875",
						"creationTimestamp":"2016-03-03T08:28:00Z",
						"labels":
									{
									"owner":"t1"
									}
					},
				"spec":
					{
						"ingress":
						    [
							{
								"from": [
										    { "podSelector": { "matchLabels" : 
										    	{"tier":"frontend"}
										    	}
											}
										],
								"ports":[
											{
												"port":80,
												"protocol":"TCP"
											
											}
											]
											
							}
							],
						"podSelector": {
							"matchLabels" : {
								"tier":"backend"
							}
							}
						}
					}
			}`
	addNamespace1 = `{"type":"ADDED","object":{
	 				"kind":"Namespace",
	 				"apiVersion":"v1",
	 				"metadata":{
	 						"name":"default",
	 						"selfLink":"/api/v1/namespaces/tenant1",
	 						"uid":"d10db271-dc03-11e5-9c86-0213e1312dc5",
	 						"resourceVersion":"6",
	 						"creationTimestamp":"2016-02-25T21:07:45Z"
	 						},
	 				"spec":{"finalizers":["kubernetes"]},"status":{"phase":"Active"}}}`
)
