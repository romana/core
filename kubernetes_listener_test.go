package kubernetes

import (
	"fmt"
	"github.com/romana/core/common"
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
	serviceURL string
	kubeURL    string
	c          *check.C
}

var _ = check.Suite(&MySuite{})

// ServeHTTP is a handler that will be used to simulate Kubernetes
func (ks kubeSimulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//	w.Header().Set("Connection", "Keep-Alive")
	//	w.Header().Set("Transfer-Encoding", "chunked")
	flusher, _ := w.(http.Flusher)

	fmt.Fprintf(w, addPolicy1)
	flusher.Flush() // Trigger "chunked" encoding and send a chunk...
	time.Sleep(10 * time.Millisecond)

	fmt.Fprintf(w, addNamespace1)
	flusher.Flush() // Trigger "chunked" encoding and send a chunk...
	time.Sleep(10 * time.Millisecond)

}

// mockSvc is a Romana Service used in tests.
type mockSvc struct{}

func (s *mockSvc) SetConfig(config common.ServiceConfig) error {
	return nil
}

func (s *mockSvc) Name() string {
	return "mockPolicySvc"
}

func (s *mockSvc) Initialize() error {
	return nil
}

func (s *mockSvc) Routes() common.Routes {
	addPolicyRoute := common.Route{
		Method:  "POST",
		Pattern: "/policies",

		Handler: func(input interface{}, ctx common.RestContext) (interface{}, error) {
			log.Printf("Received %v", input)
			switch input := input.(type) {
			case *common.Policy:
				return input, nil
			default:
				return nil, common.NewError("Expected common.Policy, got %v", input)
			}
		},
		MakeMessage: func() interface{} { return &common.Policy{} },
	}
	routes := common.Routes{
		addPolicyRoute,
	}
	return routes
}

type kubeSimulator struct {
}

type fakeRestClient struct {
	common.RestClient
	s *MySuite
}

func (frc *fakeRestClient) GetServiceURL(name string) (string, error) {
	return frc.s.serviceURL, nil
}

func (frc *fakeRestClient) GetServiceConfig(svc common.Service) (*common.ServiceConfig, error) {
	if svc.Name() == "kubernetes-listener" {
		url, _ := url.Parse(frc.s.serviceURL)
		hostPort := strings.Split(url.Host, ":")
		port, _ := strconv.ParseUint(hostPort[1], 10, 64)
		log.Printf("Looks like %s is running on %d", svc.Name(), port)
		api := &common.Api{Host: "localhost", Port: port, RootServiceUrl: frc.s.serviceURL}
		commonConfig := common.CommonConfig{Api: api}
		kubeListenerConfig := make(map[string]interface{})
		kubeListenerConfig["kubernetes_url"] = frc.s.kubeURL
		kubeListenerConfig["url_prefix"] = "apis/romana.io/demo/v1/namespaces"
		kubeListenerConfig["segment_label_name"] = "tier"
		svcConfig := common.ServiceConfig{Common: commonConfig, ServiceSpecific: kubeListenerConfig}
		return &svcConfig, nil
	} else {
		return frc.RestClient.GetServiceConfig(svc)
	}
}

type RomanaT struct {
	testing.T
}

func (s *MySuite) startListener() error {
	clientConfig := common.GetDefaultRestClientConfig(s.serviceURL)
	client0, err := common.NewRestClient(clientConfig)
	if err != nil {
		return err
	}
	client1 := fakeRestClient{RestClient: *client0, s: s}

	kubeListener := &kubeListener{}
	config, err := client1.GetServiceConfig(kubeListener)
	if err != nil {
		return err
	}
	_, err = common.InitializeService(kubeListener, *config)
	if err != nil {
		return err
	}
	return nil
}

func (s *MySuite) TestListener(c *check.C) {
	// Start Kubernetes simulator
	svr := http.Server{}
	svr.Handler = kubeSimulator{}
	svcInfo, err := common.ListenAndServe(&svr)
	if err != nil {
		c.Error(err)
	}
	s.kubeURL = fmt.Sprintf("http://%s", svcInfo.Address)
	log.Printf("Kubernetes (mock) listening on %s", s.kubeURL)

	// Start Policy server simulator
	cfg := &common.ServiceConfig{Common: common.CommonConfig{Api: &common.Api{Port: 0, RestTimeoutMillis: 100}}}
	log.Printf("Mock config: %v\n", cfg)
	svc := &mockSvc{}
	svcInfo, err = common.InitializeService(svc, *cfg)
	if err != nil {
		c.Error(err)
	}
	msg := <-svcInfo.Channel
	log.Printf("Service says %s\n", msg)
	s.serviceURL = fmt.Sprintf("http://%s", svcInfo.Address)

	// Start listener
	err = s.startListener()
	if err != nil {
		c.Error(err)
	}
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
