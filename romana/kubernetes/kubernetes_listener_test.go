package kubernetes

import (
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	//	"github.com/romana/core/policy"
	"github.com/go-check/check"
	"log"
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

// ServeHTTP is a handler that will be used to simulate Kubernetes
func (ks kubeSimulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//	w.Header().Set("Connection", "Keep-Alive")
	//	w.Header().Set("Transfer-Encoding", "chunked")
	log.Println("Test: Entered kubeSimulator ServeHTTP()")
	flusher, _ := w.(http.Flusher)

	fmt.Fprintf(w, addPolicy1)
	flusher.Flush() // Trigger "chunked" encoding and send a chunk...
	time.Sleep(10 * time.Millisecond)

	fmt.Fprintf(w, addNamespace1)
	flusher.Flush() // Trigger "chunked" encoding and send a chunk...
	time.Sleep(10 * time.Millisecond)

}

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
	addPolicyRoute := common.Route{
		Method:  "POST",
		Pattern: "/policies",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Printf("Received %#v", input)
			switch input := input.(type) {
			case *common.Policy:
				return input, nil
			default:
				return nil, common.NewError("Expected common.Policy, got %#v", input)
			}
		},
		MakeMessage: func() interface{} { return &common.Policy{} },
	}

	kubeListenerConfigRoute := common.Route{
		Method:  "GET",
		Pattern: "/config/kubernetesListener",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			json := `{"common":{"api":{"host":"0.0.0.0","port":9606}},
			"config":{"kubernetes_url":"http://localhost",
			"segment_label_name":"tier",
			"url_prefix":"apis/romana.io/demo/v1/namespaces"}}`
			return common.Raw{Body: json}, nil
		},
	}

	tenantAddRoute := common.Route{
		Method:  "POST",
		Pattern: "/tenants",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Println("In addTenant()")
			newTenant := input.(*tenant.Tenant)
			if s.tenantsStr[newTenant.ExternalID] != 0 {
				newTenant.ID = s.tenantsStr[newTenant.ExternalID]
				return nil, common.NewErrorConflict(newTenant)
			}
			s.tenantCounter += 1
			s.tenants[s.tenantCounter] = newTenant.ExternalID
			s.tenantsStr[newTenant.ExternalID] = s.tenantCounter
			newTenant.ID = s.tenantCounter
			log.Printf("In tenantAddRoute\n\t%#v\n\t%#v", s.tenants, s.tenantsStr)

			return newTenant, nil
		},
		MakeMessage: func() interface{} { return &tenant.Tenant{} },
	}

	tenantGetRoute := common.Route{
		Method:  "GET",
		Pattern: "/tenants/{tenantID}",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Printf("In tenantGetRoute\n\t%#v\n\t%#v", s.tenants, s.tenantsStr)
			idStr := ctx.PathVariables["tenantID"]
			id, err := strconv.ParseUint(idStr, 10, 64)
			if err != nil {
				if s.tenantsStr[idStr] == 0 {
					return nil, common.NewError404("tenant", idStr)
				}
				id = s.tenantsStr[idStr]
				return &tenant.Tenant{ID: id, Name: idStr, ExternalID: idStr}, nil
			}
			if id < 1 || id > s.tenantCounter {
				return nil, common.NewError404("tenant", idStr)
			}
			name := s.tenants[s.tenantCounter]
			return &tenant.Tenant{ID: id, Name: name, ExternalID: name}, nil
		},
	}

	segmentAddRoute := common.Route{
		Method:  "POST",
		// For the purpose of this test, we are going to ignore tenantID and pretend
		// it's the correct one.
		Pattern: "/tenants/{tenantID}/segments",
		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Println("In addSegment()")
			newSegment := input.(*tenant.Segment)
			newSegment.TenantID = 1
			if s.segmentsStr[newSegment.ExternalID] != 0 {
				newSegment.ID = s.segmentsStr[newSegment.ExternalID]
				return nil, common.NewErrorConflict(newSegment)
			}
			s.segmentCounter += 1
			s.segments[s.segmentCounter] = newSegment.ExternalID
			s.segmentsStr[newSegment.ExternalID] = s.segmentCounter
			newSegment.ID = s.segmentCounter
			log.Printf("In segmentAddRoute\n\t%#v\n\t%#v", s.segments, s.segmentsStr)
			return newSegment, nil
		},
		MakeMessage: func() interface{} { return &tenant.Segment{} },
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
		addPolicyRoute,
		rootRoute,
		tenantAddRoute,
		tenantGetRoute,
		segmentGetRoute,
		segmentAddRoute,
		kubeListenerConfigRoute,
		registerPortRoute,
	}
	log.Printf("mockService: Set up routes: %#v", routes)
	return routes
}

type kubeSimulator struct {
}

func (s *MySuite) getKubeListenerServiceConfig() *common.ServiceConfig {
	url, _ := url.Parse(s.serviceURL)
	hostPort := strings.Split(url.Host, ":")
	port, _ := strconv.ParseUint(hostPort[1], 10, 64)
	api := &common.Api{Host: "localhost", Port: port, RootServiceUrl: s.serviceURL}
	commonConfig := common.CommonConfig{Api: api}
	kubeListenerConfig := make(map[string]interface{})
	kubeListenerConfig["kubernetes_url"] = s.kubeURL
	kubeListenerConfig["url_prefix"] = "apis/romana.io/demo/v1/namespaces"
	kubeListenerConfig["segment_label_name"] = "tier"
	svcConfig := common.ServiceConfig{Common: commonConfig, ServiceSpecific: kubeListenerConfig}
	log.Printf("Test: Returning KubernetesListener config %#v", svcConfig.ServiceSpecific)
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
	return nil
}

func (s *MySuite) TestListener(c *check.C) {
	// Start Kubernetes simulator
	svr := &http.Server{}
	svr.Handler = &kubeSimulator{}
	log.Printf("TestListener: Calling ListenAndServe(%p)", svr)
	svcInfo, err := common.ListenAndServe(svr)
	if err != nil {
		c.Error(err)
	}
	msg := <-svcInfo.Channel
	log.Printf("TestListener: Kubernetes said %s", msg)
	s.kubeURL = fmt.Sprintf("http://%s", svcInfo.Address)
	log.Printf("Test: Kubernetes listening on %s (%s)", s.kubeURL, svcInfo.Address)

	cfg := &common.ServiceConfig{Common: common.CommonConfig{Api: &common.Api{Port: 0, RestTimeoutMillis: 100}}}
	log.Printf("Test: Mock service config:\n\t%#v\n\t%#v\n", cfg.Common.Api, cfg.ServiceSpecific)
	svc := &mockSvc{mySuite: s}
	svc.tenants = make(map[uint64]string)
	svc.tenantsStr = make(map[string]uint64)
	svc.segments = make(map[uint64]string)
	svc.segmentsStr = make(map[string]uint64)
	svcInfo, err = common.InitializeService(svc, *cfg)
	if err != nil {
		c.Error(err)
	}
	msg = <-svcInfo.Channel
	log.Printf("Test: Mock service says %s\n", msg)
	s.serviceURL = fmt.Sprintf("http://%s", svcInfo.Address)
	log.Printf("Test: Mock service listens at %s\n", s.serviceURL)

	// Start listener
	err = s.startListener()
	if err != nil {
		c.Error(err)
	}
	log.Printf("Test: KubeListener started\n")

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
						"selfLink":"/apis/romana.io/demo/v1/namespaces/tenant1/networkpolicys/policy1",
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
						"allowIncoming":
							{
								"from": [
										    { "pods":
										    	{"tier":"frontend"}
											}
										],
								"toPorts":[
											{
												"port":80,
												"protocol":"TCP"
											
											}
											]
							},
						"podSelector":
							{
								"tier":"backend"
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
