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
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
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

// KubeListener is a Service that listens to updates
// from Kubernetes by connecting to the endpoints specified
// and consuming chunked JSON documents. The endpoints are
// constructed from kubeURL and the following paths:
// 1. namespaceNotificationPath for namespace additions/deletions
// 2. policyNotificationPathPrefix + <namespace name> + policyNotificationPathPostfix
//    for policy additions/deletions.
type KubeListener struct {
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
func (l *KubeListener) Routes() common.Routes {
	routes := common.Routes{}
	return routes
}

// Name implements method of Service interface.
func (l *KubeListener) Name() string {
	return "kubernetesListener"
}

func (l *KubeListener) CreateSchema(overwrite bool) error {
	return nil
}

// SetConfig implements SetConfig function of the Service interface.
func (l *KubeListener) SetConfig(config common.ServiceConfig) error {
	// confString used only for trace log, to quickly help find
	// in which file and where the variables listed below are.
	confString := "/etc/romana/romana.conf.yml:kubernetesListener:config:"
	log.Trace(trace.Inside, confString, config)

	m := config.ServiceSpecific
	if kl, ok := m["kubernetes_url"]; !ok || kl == "" {
		return fmt.Errorf("%s%s", confString, "kubernetes_url required in config.")
	}
	l.kubeURL = m["kubernetes_url"].(string)

	if nnp, ok := m["namespace_notification_path"]; !ok || nnp == "" {
		return fmt.Errorf("%s%s", confString, "namespace_notification_path required in config.")
	}
	l.namespaceNotificationPath = m["namespace_notification_path"].(string)

	if pnppre, ok := m["policy_notification_path_prefix"]; !ok || pnppre == "" {
		return fmt.Errorf("%s%s", confString, "policy_notification_path_prefix required in config.")
	}
	l.policyNotificationPathPrefix = m["policy_notification_path_prefix"].(string)

	if pnppost, ok := m["policy_notification_path_prefix"]; !ok || pnppost == "" {
		return fmt.Errorf("%s%s", confString, "policy_notification_path_postfix required in config.")
	}
	l.policyNotificationPathPostfix = m["policy_notification_path_postfix"].(string)

	if sln, ok := m["segment_label_name"]; !ok || sln == "" {
		return fmt.Errorf("%s%s", confString, "segment_label_name required in config.")
	}
	l.segmentLabelName = m["segment_label_name"].(string)

	if tln, ok := m["tenant_label_name"]; !ok || tln == "" {
		return fmt.Errorf("%s%s", confString, "tenant_label_name required in config.")
	}
	l.tenantLabelName = m["tenant_label_name"].(string)

	l.namespaceBufferSize = 1000

	if kc, ok := m["kubernetes_config"]; !ok || kc == "" {
		// Default kubernetes config location on ubuntu
		// TODO: this should not be hard coded, other
		//       distributions may have other user names.
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
		return fmt.Errorf("Failed to make kubernetes client %s", err)
	}
	l.kubeClient = clientset

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
	KubeListener := &KubeListener{}
	KubeListener.restClient = client

	config, err := client.GetServiceConfig(KubeListener.Name())
	if err != nil {
		return nil, err
	}
	return common.InitializeService(KubeListener, *config, cred)
}

// getOrAddSegment finds a segment (based on segment selector).
// If not found, it adds one.
func (l *KubeListener) getOrAddSegment(namespace string, kubeSegmentName string) (*tenant.Segment, error) {
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
func (l *KubeListener) resolveTenantByName(tenantName string) (*tenant.Tenant, error) {
	t := &tenant.Tenant{Name: tenantName}
	err := l.restClient.Find(t, common.FindLast)
	if err != nil {
		return t, err
	}
	return t, nil
}

// deleteNetworkPolicyByID deletes the policy specified by the policyID
func (l *KubeListener) deleteNetworkPolicyByID(policyID uint64) error {
	policyURL, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		return err
	}
	policyURL = fmt.Sprintf("%s/policies/%d", policyURL, policyID)
	log.Debugf("deleteNetworkPolicyByID: Deleting policy %d", policyID)
	deletedPolicy := common.Policy{}
	err = l.restClient.Delete(policyURL, nil, &deletedPolicy)
	if err != nil {
		switch err := err.(type) {
		default:
			return err
		case common.HttpError:
			if err.StatusCode == http.StatusNotFound {
				log.Warnf("deleteNetworkPolicyByID: Policy %d not found, ignoring", policyID)
				return nil
			} else {
				return err
			}
		}
	}
	log.Debugf("deleteNetworkPolicyByID: Deleted policy %s", deletedPolicy)
	return err
}

// addNetworkPolicy adds the policy to the policy service.
func (l *KubeListener) addNetworkPolicy(policy common.Policy) error {
	policyURL, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		return err
	}
	policyURL = fmt.Sprintf("%s/policies", policyURL)
	log.Debugf("Applying policy %s", policy)
	err = l.restClient.Post(policyURL, policy, &policy)
	if err != nil {
		return err
	}
	return nil
}

// deleteNetworkPolicy deletes the policy matching provided policy on whatever
// fields are provided.
func (l *KubeListener) deleteNetworkPolicy(policy common.Policy) error {
	policyURL, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		return err
	}

	rPolicy := common.Policy{}
	policyURL = fmt.Sprintf("%s/find/policies/%s", policyURL, policy.Name)
	err = l.restClient.Get(policyURL, &rPolicy)
	if err != nil {
		switch err := err.(type) {
		default:
			return err
		case common.HttpError:
			if err.StatusCode == http.StatusNotFound {
				log.Warnf("deleteNetworkPolicy: Policy not found %s, ignoring", policy.Name)
				return nil
			} else {
				return err
			}
		}
	}
	return l.deleteNetworkPolicyByID(rPolicy.ID)
}

func (l *KubeListener) Initialize(client *common.RestClient) error {
	l.restClient = client

	// TODO, find a better place to initialize
	// the translator. Stas.
	PTranslator.Init(l.restClient, l.segmentLabelName, l.tenantLabelName)
	tc := PTranslator.GetClient()
	if tc == nil {
		log.Critical("Failed to initialize rest client for policy translator.")
		os.Exit(255)
	}

	// Channel for stopping watching kubernetes events.
	done := make(chan struct{})

	// l.ProcessNodeEvents listens and processes kubernetes node events,
	// mainly allowing nodes to be added/removed to/from romana cluster
	// based on these events.
	l.ProcessNodeEvents(done)

	l.lastEventPerNamespace = make(map[string]uint64)
	log.Infof("%s: Starting server", l.Name())
	nsURL, err := common.CleanURL(fmt.Sprintf("%s/%s/?%s", l.kubeURL, l.namespaceNotificationPath, HttpGetParamWatch))
	if err != nil {
		return err
	}
	log.Infof("Starting to listen on %s", nsURL)
	eventc, err := l.nsWatch(done, nsURL)
	if err != nil {
		log.Critical("Namespace watcher failed to start", err)
		os.Exit(255)
	}

	l.process(eventc, done)

	ProduceNewPolicyEvents(eventc, done, l)

	log.Info("All routines started")
	return nil
}

// CreateSchema is placeholder for now.
func CreateSchema(rootServiceURL string, overwrite bool) error {
	return nil
}
