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

// Package kubernetes listens to Kubernetes for policy updates.
package kubernetes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"io"
	"log"
	"net/http"
	"strings"
)

// readChunk reads the next chunk from the provided reader.
func readChunk(reader io.Reader) ([]byte, error) {
	var result []byte
	for {
		buf := make([]byte, bytes.MinRead)
		n, err := reader.Read(buf)
		if n < bytes.MinRead {
			result = append(result, buf[0:n]...)
			if err != nil {
				return result, err
			}
			break
		}
		result = append(result, buf...)
	}
	return result, nil
}

type networkPolicyAction int

const (
	networkPolicyActionDelete networkPolicyAction = iota
	networkPolicyActionAdd
	networkPolicyActionModify
)

// kubeListener is a Service that listens to updates
// from Kubernetes by connecting to the endpoints specified
// and consuming chunked JSON documents. The endpoints are
// constructed from kubeURL and the following paths:
// 1. namespaceNotificationPath for namespace additions/deletions
// 2. policyNotificationPathPrefix + <namespace name> + policyNotificationPathPostfix
//    for policy additions/deletions.
type kubeListener struct {
	config                        common.ServiceConfig
	restClient                    *common.RestClient
	kubeURL                       string
	namespaceNotificationPath     string
	policyNotificationPathPrefix  string
	policyNotificationPathPostfix string
	segmentLabelName              string
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
		return errors.New("kubernetes_url required")
	}
	l.kubeURL = m["kubernetes_url"].(string)

	if m["namespace_notification_path"] == "" {
		return errors.New("namespace_notification_path required")
	}
	l.namespaceNotificationPath = m["namespace_notification_path"].(string)

	if m["policy_notification_path_prefix"] == "" {
		return errors.New("policy_notification_path_prefix required")
	}
	l.policyNotificationPathPrefix = m["policy_notification_path_prefix"].(string)

	if m["policy_notification_path_postfix"] == "" {
		return errors.New("policy_notification_path_postfix required")
	}
	l.policyNotificationPathPostfix = m["policy_notification_path_postfix"].(string)

	if m["segment_label_name"] == "" {
		return errors.New("segment_label_name required")
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

// getOrAddSegment finds a segment (based on segment selector).
// If not found, it adds one.
func (l *kubeListener) getOrAddSegment(namespace string, kubeSegmentName string) (*tenant.Segment, error) {
	ten := &tenant.Tenant{}
	ten.Name = namespace
	// TODO this should be changed to find EXACTLY one after deletion functionality is implemented
	err := l.restClient.Find(ten, common.FindLast)
	if err != nil {
		return nil, err
	}

	seg := &tenant.Segment{}
	seg.Name = kubeSegmentName
	seg.TenantID = ten.ID
	err = l.restClient.Find(seg, common.FindExactlyOne)
	if err == nil {
		return seg, nil
	}

	switch err := err.(type) {
	case common.HttpError:
		if err.StatusCode == http.StatusNotFound {
			// Not found, so let's create a segment.
			segreq := tenant.Segment{Name: kubeSegmentName, TenantID: ten.ID}
			segURL, err2 := l.restClient.GetServiceUrl("tenant")
			if err2 != nil {
				return nil, err2
			}
			segURL = fmt.Sprintf("%s/tenants/%d/segments", segURL, ten.ID)
			err2 = l.restClient.Post(segURL, segreq, seg)
			if err2 == nil {
				// Successful creation.
				return seg, nil
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

// resolveTenantByName retrieves tenant information from romana.
func (l *kubeListener) resolveTenantByName(tenantName string) (*tenant.Tenant, error) {
	t := &tenant.Tenant{Name: tenantName}
	err := l.restClient.Find(t, common.FindLast)
	if err != nil {
		return t, err
	}
	return t, nil
}

// translateNetworkPolicy translates a Kubernetes policy into
// Romana policy (see common.Policy) with the following rules:
// 1. Kubernetes Namespace corresponds to Romana Tenant
// 2. If Romana Tenant does not exist it is an error (a tenant should
//    automatically have been created when the namespace was added)
func (l *kubeListener) translateNetworkPolicy(kubePolicy *KubeObject) (common.Policy, error) {
	policyName := kubePolicy.Metadata.Name
	romanaPolicy := &common.Policy{Direction: common.PolicyDirectionIngress, Name: policyName, ExternalID: policyName}
	ns := kubePolicy.Metadata.Namespace
	// TODO actually look up tenant K8S ID.
	t, err := l.resolveTenantByName(ns)
	log.Printf("translateNetworkPolicy(): For namespace %s got %+v / %+v", ns, t, err)
	if err != nil {
		return *romanaPolicy, err
	}
	tenantID := t.ID
	tenantExternalID := t.ExternalID

	kubeSegmentID := kubePolicy.Spec.PodSelector.MatchLabels[l.segmentLabelName]
	if kubeSegmentID == "" {
		return *romanaPolicy, common.NewError("Expected segment to be specified in podSelector part as '%s'", l.segmentLabelName)
	}

	segment, err := l.getOrAddSegment(ns, kubeSegmentID)
	if err != nil {
		return *romanaPolicy, err
	}
	segmentID := segment.ID
	appliedTo := common.Endpoint{TenantID: tenantID, SegmentID: segmentID}
	romanaPolicy.AppliedTo = make([]common.Endpoint, 1)
	romanaPolicy.AppliedTo[0] = appliedTo
	romanaPolicy.Peers = []common.Endpoint{}
	romanaPolicy.Rules = common.Rules{}
	// TODO range
	// from := kubePolicy.Spec.Ingress[0].From
	// This is subject to change once the network specification in Kubernetes is finalized.
	// Right now it is a work in progress.
	for _, ingress := range kubePolicy.Spec.Ingress {
		for _, entry := range ingress.From {
			pods := entry.Pods
			fromKubeSegmentID := pods.MatchLabels[l.segmentLabelName]
			if fromKubeSegmentID == "" {
				return *romanaPolicy, common.NewError("Expected segment to be specified in podSelector part as '%s'", l.segmentLabelName)
			}
			fromSegment, err := l.getOrAddSegment(ns, fromKubeSegmentID)
			if err != nil {
				return *romanaPolicy, err
			}
			peer := common.Endpoint{TenantID: tenantID, TenantExternalID: tenantExternalID, SegmentID: fromSegment.ID, SegmentExternalID: fromSegment.ExternalID}
			romanaPolicy.Peers = append(romanaPolicy.Peers, peer)
		}
		// TODO range
		// toPorts := kubePolicy.Spec.Ingress[0].ToPorts
		for _, toPort := range ingress.ToPorts {
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
	policyURL, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		return err
	}
	policyURL = fmt.Sprintf("%s/policies", policyURL)
	policyStr, _ := json.Marshal(romanaNetworkPolicy)
	switch action {
	case networkPolicyActionAdd:
		log.Printf("Applying policy %s", policyStr)
		err := l.restClient.Post(policyURL, romanaNetworkPolicy, &romanaNetworkPolicy)
		if err != nil {
			return err
		}
	case networkPolicyActionDelete:
		log.Printf("Deleting policy policy %s", policyStr)
		err := l.restClient.Delete(policyURL, romanaNetworkPolicy, &romanaNetworkPolicy)
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
	nsURL, err := common.CleanURL(fmt.Sprintf("%s%s", l.kubeURL, l.namespaceNotificationPath))
	if err != nil {
		return err
	}
	log.Printf("Starting to listen on %s", nsURL)
	done := make(chan Done)
	nsEvents, err := l.nsWatch(done, nsURL)
	if err != nil {
		log.Fatal("Namespace watcher failed to start", err)
	}

	events := l.conductor(nsEvents, done)
	l.process(events, done)
	log.Println("All routines started")
	return nil
}

// CreateSchema is placeholder for now.
func CreateSchema(rootServiceURL string, overwrite bool) error {
	return nil
}
