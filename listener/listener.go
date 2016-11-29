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

// Package listener listens to Kubernetes for policy updates.
package listener

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	log "github.com/romana/rlog"

	"k8s.io/client-go/1.5/kubernetes"
	"k8s.io/client-go/1.5/tools/cache"
	"k8s.io/client-go/1.5/tools/clientcmd"
)

type networkPolicyAction int

const (
	networkPolicyActionDelete networkPolicyAction = iota
	networkPolicyActionAdd
	networkPolicyActionModify
)

const (
	HttpGetParamWatch           = "watch=true"
	HttpGetParamResourceVersion = "resourceVersion"
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
	tenantLabelName               string
	lastEventPerNamespace         map[string]uint64
	namespaceBufferSize           uint64

	kubeClient *kubernetes.Clientset
	Watchers   map[string]cache.ListerWatcher
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

	if m["tenant_label_name"] == "" {
		return errors.New("segment_label_name required")
	}
	l.tenantLabelName = m["tenant_label_name"].(string)

	// TODO, what is `wait_for_iface_try` and why namespaceBufferSize is set instead ? Stas.
	if m["wait_for_iface_try"] == nil {
		l.namespaceBufferSize = 10
	} else {
		l.namespaceBufferSize = uint64(m["namespace_buffer_size"].(float64))
	}
	l.namespaceBufferSize = 1000

	if m["kubernetes_config"] == nil {
		m["kubernetes_config"] = "/home/ubuntu/.kube/config"
	}

	// TODO, this loads kubernetes config from flags provided in main
	// should be loading from path provided by romana-root. Stas.
	kubeClientConfig, err := clientcmd.BuildConfigFromFlags("", m["kubernetes_config"].(string))
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to load kubernetes kubeClientConfig %s", err))
	}
	clientset, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to make kubernetes client %s", err))
	}
	l.kubeClient = clientset

	// TODO, find a better place to initialize
	// the translator. Stas.
	PTranslator.Init(l.restClient, l.segmentLabelName, l.tenantLabelName)
	tc := PTranslator.GetClient()
	if tc == nil {
		log.Critical("Failed to initialize rest client for policy translator.")
		os.Exit(255)
	}

	return nil
}

// TODO there should be a better way to introduce translator
// then global variable like this one.
var PTranslator Translator

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

func (l *kubeListener) applyNetworkPolicy(action networkPolicyAction, romanaNetworkPolicy common.Policy) error {
	policyURL, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		return err
	}
	policyURL = fmt.Sprintf("%s/policies", policyURL)
	policyStr, _ := json.Marshal(romanaNetworkPolicy)
	switch action {
	case networkPolicyActionAdd:
		log.Infof("Applying policy %s", policyStr)
		err := l.restClient.Post(policyURL, romanaNetworkPolicy, &romanaNetworkPolicy)
		if err != nil {
			return err
		}
	case networkPolicyActionDelete:
		log.Infof("Deleting policy policy %s", policyStr)
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
	l.lastEventPerNamespace = make(map[string]uint64)
	log.Infof("%s: Starting server", l.Name())
	nsURL, err := common.CleanURL(fmt.Sprintf("%s/%s/?%s", l.kubeURL, l.namespaceNotificationPath, HttpGetParamWatch))
	if err != nil {
		return err
	}
	log.Infof("Starting to listen on %s", nsURL)
	done := make(chan struct{})
	eventc, err := l.nsWatch(done, nsURL)
	if err != nil {
		log.Critical("Namespace watcher failed to start", err)
		os.Exit(255)
	}

	// events := l.conductor(nsEvents, done)
	l.process(eventc, done)

	ProduceNewPolicyEvents(eventc, done, l)

	log.Info("All routines started")
	return nil
}

// CreateSchema is placeholder for now.
func CreateSchema(rootServiceURL string, overwrite bool) error {
	return nil
}
