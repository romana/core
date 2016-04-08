package kubernetes

import (
	"fmt"
	"github.com/romana/core/common"
	//	"github.com/romana/core/policy"
	"log"
	"net/http"
	"testing"
	"time"
)

// mockPolicySvc is a Romana Service used in tests.
type mockPolicySvc struct{}

func (s mockPolicySvc) SetConfig(config common.ServiceConfig) error {
	return nil
}

func (s mockPolicySvc) Name() string {
	return "mockPolicySvc"
}

func (s mockPolicySvc) Initialize() error {
	return nil
}

type kubeSimulator struct {
}

func TestListener(t *testing.T) {
	// Start Kubernetes simulator
	svr := http.Server{}
	svr.Handler = kubeSimulator{}
	svcInfo, err := common.ListenAndServe(&svr)
	if err != nil {
		t.Error(err)
	}
	kubeUrl := fmt.Sprintf("http://%s", svcInfo.Address)
	log.Printf("Kubernetes (mock) listening on %s", kubeUrl)

	// Start Policy server simulator
	cfg := &common.ServiceConfig{Common: common.CommonConfig{Api: &common.Api{Port: 0, RestTimeoutMillis: 100}}}
	log.Printf("Mock config: %v\n", cfg)
	svc := &mockPolicySvc{}
	svcInfo, err = common.InitializeService(svc, *cfg)
	if err != nil {
		t.Error(err)
	}
	msg := <-svcInfo.Channel
	log.Printf("Service says %s\n", msg)

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
	 testNs = `{"type":"ADDED","object":{
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


 obj["object"]["metadata"]["namespace"]
// +<         rule["dst_tenant"] = rule["src_tenant"]
// +<         rule["dst_segment"] = obj["object"]["spec"]["podSelector"]["segment"]
// +<         rule["src_segment"] = obj["object"]["spec"]["allowIncoming"]["from"][0]["pods"]["segment"]
// +<         rule["port"] = obj["object"]["spec"]["allowIncoming"]["toPorts"][0]["port"]
// +<         rule["protocol"] = obj["object"]["spec"]["allowIncoming"]["toPorts"][0]["protocol"]


func (ks kubeSimulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//	w.Header().Set("Connection", "Keep-Alive")
	//	w.Header().Set("Transfer-Encoding", "chunked")
	flusher, _ := w.(http.Flusher)

	
		fmt.Fprintf(w, addPolicy1)
		flusher.Flush() // Trigger "chunked" encoding and send a chunk...
		time.Sleep(100 * time.Millisecond)
	
}

func (s mockPolicySvc) Routes() common.Routes {
	routes := common.Routes{
		common.Route{
			"POST",
			"/policies",
			func(input interface{}, ctx common.RestContext) (interface{}, error) {
				inp := input.(common.UnwrappedRestHandlerInput)
				writer := inp.ResponseWriter
				c, err := writer.Write([]byte("hello world"))
				log.Printf("/normal: Wrote output count %d, error %v, now is %v\n", c, err, time.Now())
				return nil, nil
			},
			func() interface{} {
				return http.Request{}
			},
			false,
			nil,
		},
	}
	return routes
}
