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

// Listens to Kubernetes for policy updates
package kubernetes

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"io"
	"log"
	"net/http"
	"strings"
	//	"encoding/json"
	//	"time"
	//	"net/http"
	//	"runtime"
)

// readChunk reads the next chunk from the provided reader.
func readChunk(reader io.Reader) ([]byte, error) {
	result := make([]byte, 0)
	for {
		buf := make([]byte, bytes.MinRead)
		n, err := reader.Read(buf)
		if n < bytes.MinRead {
			result = append(result, buf[0:n]...)
			if err != nil {
				return result, err
			} else {
				break
			}
		}
		result = append(result, buf...)
	}
	return result, nil
}

// listen connects to kubernetesURL and sends each
// chunk received to the ch channel. It exits on an
// error.
//func listen(ch chan []byte, kubernetesURL string) {
//	log.Printf("Listening to %s, currently %d goroutines are running", kubernetesURL, runtime.NumGoroutine())
//	resp, err := http.Get(kubernetesURL)
//	if err != nil {
//		log.Printf("Error connecting: %#v", err)
//		log.Println("Closing channel")
//		close(ch)
//		log.Println("Exiting goroutine")
//		return
//	}
//	//	chunkedReader := resp.Body
//	for {
//		chunk, err := readChunk(resp.Body)
//		if err != nil {
//			if err != io.EOF {
//				log.Printf("Error reading chunk: %#v", err)
//			}
//			if len(chunk) != 0 {
//				ch <- chunk
//			}
//			log.Println("Closing channel")
//			close(ch)
//			log.Println("Exiting goroutine")
//			return
//		}
//		if len(chunk) != 0 {
//			time.Sleep(1 * time.Millisecond)
//		} else {
//			ch <- chunk
//		}
//	}
//}

// processChunk processes a chunk received from Kubernetes. A chunk
// is a new update.
//func processChunk(chunk []byte) error {
//	m := make(map[string]interface{})
//	err := json.Unmarshal(chunk, &m)
//	if err != nil {
//		return err
//	}
//	method := m["method"]
//	if method == nil {
//		return errors.New("Expected 'method' field")
//	}
//	methodStr = strings.ToLower(method.(string))
//	networkPolicyIfc := m["policy_definition"]
//	if networkPolicyIfc == nil {
//		return errors.New("Expected 'policy_definition' field")
//	}
//	kubeNetworkPolicy := networkPolicyIfc.(map[string]interface{})
//	romanaNetworkPolicy, err := translateNetworkPolicy(kubeNetworkPolicy)
//	if err != nil {
//		return err
//	}
//
//	if methodStr == "added" {
//		applyNetworkPolicy(networkPolicyActionAdd, romanaNetworkPolicy)
//	} else if methodStr == "deleted" {
//		applyNetworkPolicy(networkPolicyActioDelete, romanaNetworkPolicy)
//	} else if methodStr == "modified" {
//		applyNetworkPolicy(networkPolicyActioModify, romanaNetworkPolicy)
//	} else {
//		return common.NewError("Unexpected method '%s'", methodStr)
//	}
//}

// Run implements the main loop, reconnecting as needed.
//func RunListener0(rootURL string, kubeURL string) {
//	l := kubeListener{kubeURL: kubeURL, restClient: common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))}
//	l.Run()
//}
//
//func (l kubeListener) Run0() {
//	for {
//		ch := make(chan []byte)
//		go listen(ch, l.kubernetesURL)
//		for {
//			chunk, ok := <-ch
//			log.Println(ok)
//			if chunk != "" {
//				log.Printf("Read chunk %#v\n%s\n------------", ok, string(chunk))
//				err = processChunk(chunk)
//				if err != nil {
//					// TODO is there any other way to handle this?
//					log.Printf("Error processing chunk %s: %#v", string(chunk), err)
//				}
//			}
//			if !ok {
//				break
//			}
//		}
//	}
//}

/////////////////////////////////////////////////////////////

type networkPolicyAction int

const (
	networkPolicyActionDelete networkPolicyAction = iota
	networkPolicyActionAdd
	networkPolicyActionModify
)

type kubeListener struct {
	config                    common.ServiceConfig
	restClient                *common.RestClient
	kubeUrl                   string
	namespaceNotificationPath string
	policyNotificationPathPrefix string
	policyNotificationPathPostfix string
	segmentLabelName          string
}

// Routes returns various routes used in the service.
func (l *kubeListener) Routes() common.Routes {
	routes := common.Routes{}
	return routes
}

// Name implements method of Service interface.
func (l *kubeListener) Name() string {
	return "kubernetesListener"
}

// SetConfig implements SetConfig function of the Service interface.
func (l *kubeListener) SetConfig(config common.ServiceConfig) error {
	m := config.ServiceSpecific
	if m["kubernetes_url"] == "" {
		return errors.New("kubernetes_url required.")
	}
	l.kubeUrl = m["kubernetes_url"].(string)
	
	if m["namespace_notification_path"] == "" {
		return errors.New("namespace_notification_path required.")
	}
	l.namespaceNotificationPath = m["namespace_notification_path"].(string)
	
	if m["policy_notification_path_prefix"] == "" {
		return errors.New("policy_notification_path_prefix required.")
	}
	l.policyNotificationPathPrefix = m["policy_notification_path_prefix"].(string)
	
	
	if m["policy_notification_path_postfix"] == "" {
		return errors.New("policy_notification_path_postfix required.")
	}
	l.policyNotificationPathPostfix = m["policy_notification_path_postfix"].(string)
	
	if m["segment_label_name"] == "" {
		return errors.New("segment_label_name required.")
	}
	l.segmentLabelName = m["segment_label_name"].(string)
	
	return nil
}

// Run configures and runs listener service.
func Run(rootServiceURL string, cred *common.Credential) (*common.RestServiceInfo, error) {
	clientConfig := common.GetDefaultRestClientConfig(rootServiceURL)
	clientConfig.Credential = cred
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		return nil, err
	}
	kubeListener := &kubeListener{}
	kubeListener.restClient = client
	config, err := client.GetServiceConfig(kubeListener.Name())
	if err != nil {
		return nil, err
	}
	return common.InitializeService(kubeListener, *config)
}

// getOrAddSegment finds a segment (based on segment selector)
//
func (l *kubeListener) getOrAddSegment(tenantServiceURL string, namespace string, kubeSegmentID string) (*tenant.Segment, error) {
	segment := &tenant.Segment{}
	segmentsURL := fmt.Sprintf("%s/tenants/%s/segments", tenantServiceURL, namespace)
	err := l.restClient.Get(fmt.Sprintf("%s/%s", segmentsURL, kubeSegmentID), segment)
	if err == nil {
		return segment, nil
	}
	switch err := err.(type) {
	case common.HttpError:
		if err.StatusCode == http.StatusNotFound {
			// Not found, so let's create a segment.
			segreq := tenant.Segment{Name: kubeSegmentID, ExternalID: kubeSegmentID}
			err2 := l.restClient.Post(segmentsURL, segreq, segment)
			if err2 == nil {
				// Successful creation.
				return segment, nil
			}
			// Creation of non-existing segment gave an error.
			switch err2 := err2.(type) {
			case common.HttpError:
				// Maybe someone else just created a segment between the original
				// lookup and now?
				if err2.StatusCode == http.StatusConflict {
					switch details := err2.Details.(type) {
					case tenant.Segment:
						// We expect the existing segment to be returned in the details field.
						return &details, nil
					default:
						// This is unexpected...
						return nil, err
					}
				}
				// Any other HTTP error other than a Conflict here - return it.
				return nil, err2
			default:
				// Any other error - return it
				return nil, err2
			}
		}
		// Any other HTTP error other than a Not found here - return it
		return nil, err
	default:
		// Any other error - return it
		return nil, err
	}
}

// translateNetworkPolicy translates a Kubernetes policy into
// Romana policy (see common.Policy) with the following rules:
// 1. Kubernetes Namespace corresponds to Romana Tenant
// 2. If Romana Tenant does not exist it is an error (a tenant should
//    automatically have been created when the namespace was added)
func (l *kubeListener) translateNetworkPolicy(kubePolicy *KubeObject) (common.Policy, error) {
	log.Printf("translateNetworkPolicy(): Received %#v", kubePolicy)
	romanaPolicy := &common.Policy{Direction: common.PolicyDirectionIngress}
	ns := kubePolicy.Metadata.Namespace
	tenantURL, err := l.restClient.GetServiceUrl("tenant")
	if err != nil {
		return *romanaPolicy, err
	}
	t := &tenant.Tenant{}
	err = l.restClient.Get(fmt.Sprintf("%s/tenants/%s", tenantURL, ns), t)
	log.Printf("translateNetworkPolicy(): For namespace %s got %#v / %#v", ns, t, err)
	if err != nil {
		return *romanaPolicy, err
	}
	tenantId := t.ID
	tenantExternalId := t.ExternalID

	kubeSegmentID := kubePolicy.Spec.PodSelector[l.segmentLabelName]
	if kubeSegmentID == "" {
		return *romanaPolicy, common.NewError("Expected segment to be specified in podSelector part as '%s'", l.segmentLabelName)
	}

	segment, err := l.getOrAddSegment(tenantURL, ns, kubeSegmentID)
	if err != nil {
		return *romanaPolicy, err
	}
	segmentId := segment.ID
	appliedTo := common.Endpoint{TenantID: tenantId, SegmentID: segmentId}
	romanaPolicy.AppliedTo = make([]common.Endpoint, 1)
	romanaPolicy.AppliedTo[0] = appliedTo
	romanaPolicy.Peers = []common.Endpoint{}
	from := kubePolicy.Spec.AllowIncoming.From
	// This is subject to change once the network specification in Kubernetes is finalized.
	// Right now it is a work in progress.
	if from != nil {
		for _, entry := range from {
			pods := entry.Pods
			fromKubeSegmentID := pods[l.segmentLabelName]
			if fromKubeSegmentID == "" {
				return *romanaPolicy, common.NewError("Expected segment to be specified in podSelector part as '%s'", l.segmentLabelName)
			}
			fromSegment, err := l.getOrAddSegment(tenantURL, ns, fromKubeSegmentID)
			if err != nil {
				return *romanaPolicy, err
			}
			peer := common.Endpoint{TenantID: tenantId, TenantExternalID: tenantExternalId, SegmentID: fromSegment.ID, SegmentExternalID: fromSegment.ExternalID}
			romanaPolicy.Peers = append(romanaPolicy.Peers, peer)
		}
		toPorts := kubePolicy.Spec.AllowIncoming.ToPorts
		romanaPolicy.Rules = common.Rules{}
		for _, toPort := range toPorts {
			proto := strings.ToLower(toPort.Protocol)
			ports := []uint{toPort.Port}
			rule := common.Rule{Protocol: proto, Ports: ports}
			romanaPolicy.Rules = append(romanaPolicy.Rules, rule)
		}
	}
	err = romanaPolicy.Validate()
	if err != nil {
		return *romanaPolicy, err
	}
	return *romanaPolicy, nil
}

func (l *kubeListener) applyNetworkPolicy(action networkPolicyAction, romanaNetworkPolicy common.Policy) error {
	policyUrl, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		return err
	}
	policyUrl = fmt.Sprintf("%s/policies", policyUrl)
	switch action {
	case networkPolicyActionAdd:
		err := l.restClient.Post(policyUrl, romanaNetworkPolicy, &romanaNetworkPolicy)
		if err != nil {
			return err
		}
		log.Printf("Applied policy %#v", romanaNetworkPolicy)
	case networkPolicyActionDelete:
		policyUrl = fmt.Sprintf("%s/%d", policyUrl, romanaNetworkPolicy.ID)
		err := l.restClient.Delete(policyUrl, nil, &romanaNetworkPolicy)
		if err != nil {
			return err
		}
	default:
		return errors.New("Unsupported operation")
	}
	return nil
}

func (l *kubeListener) Initialize() error {
	log.Printf("%s: Starting server", l.Name())
	nsUrl, err := common.CleanURL(fmt.Sprintf("%s%s", l.kubeUrl, l.namespaceNotificationPath))
	if err != nil {
		return err
	}
	log.Printf("Starting to listen on %s", nsUrl)
	done := make(chan Done)
	nsEvents, err := l.nsWatch(done, nsUrl)
	if err != nil {
		log.Fatal("Namespace watcher failed to start", err)
	}

	events := l.conductor(nsEvents, done)
	l.process(events, done)
	log.Println("All routines started")
	return nil
}

func CreateSchema(rootServiceURL string, overwrite bool) error {
	return nil
}
