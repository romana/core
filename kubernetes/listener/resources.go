// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"github.com/golang/glog"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"io"
	"net/http"
	"strings"
	"time"

	"k8s.io/client-go/1.5/pkg/api"
	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.5/pkg/fields"
	"k8s.io/client-go/1.5/tools/cache"
)

const (
	selector = "podSelector"
)

// Event is a representation of a structure that we receive from kubernetes API.
type Event struct {
	Type   string `json:"Type"`
	Object interface{}
}

const (
	KubeEventAdded    = "ADDED"
	KubeEventDeleted  = "DELETED"
	KubeEventModified = "MODIFIED"
)

// handleNetworkPolicyEvents by creating or deleting romana policies.
func handleNetworkPolicyEvents(events []Event, l *kubeListener) {
	// TODO optimise deletion, search policy by name/id
	// and delete by id rather then sending full policy body.
	// Stas.
	var deleteEvents []v1beta1.NetworkPolicy
	var createEvents []v1beta1.NetworkPolicy

	for _, event := range events {
		switch event.Type {
		case KubeEventAdded:
			createEvents = append(createEvents, *event.Object.(*v1beta1.NetworkPolicy))
		case KubeEventDeleted:
			deleteEvents = append(deleteEvents, *event.Object.(*v1beta1.NetworkPolicy))
		default:
			glog.V(3).Info("Ignoring %s event in handleNetworkPolicyEvents", event.Type)
		}
	}

	// Translate new network policies into romana policies.
	createPolicyList, kubePolicy, err := PTranslator.Kube2RomanaBulk(createEvents)
	if err != nil {
		glog.Errorf("Not all kubernetes policies could be translated to Romana policies. Attempted %d, succes %d, fail %d, error %s", len(createEvents), len(createPolicyList), len(kubePolicy), err)
	}
	for kn, _ := range kubePolicy {
		glog.Errorf("Failed to translate kubernetes policy %v", kubePolicy[kn])
	}

	// Translate old network policies into romana policies.
	// TODO this feels strange but we have to have a full policy body
	// for deletion. Stas.
	deletePolicyList, kubePolicy, err := PTranslator.Kube2RomanaBulk(deleteEvents)
	if err != nil {
		glog.Errorf("Not all kubernetes policies could be translated to Romana policies. Attempted %d, succes %d, fail %d, error %s", len(createEvents), len(deletePolicyList), len(kubePolicy), err)
	}
	for kn, _ := range kubePolicy {
		glog.Errorf("Failed to translate kubernetes policy %v", kubePolicy[kn])
	}

	// Create new policies.
	for pn, _ := range createPolicyList {
		l.applyNetworkPolicy(networkPolicyActionAdd, createPolicyList[pn])
	}

	// Delete old policies.
	for pn, _ := range deletePolicyList {
		l.applyNetworkPolicy(networkPolicyActionDelete, deletePolicyList[pn])
	}
}

// handleNamespaceEvent by creating or deleting romana tenants.
func handleNamespaceEvent(e Event, l *kubeListener) {
	namespace, ok := e.Object.(*v1.Namespace)
	if !ok {
		panic("Failed to cast namespace in handleNamespaceEvent")
	}

	glog.Infof("KubeEvent: Processing namespace event == %v and phase %v", e.Type, namespace.Status)

	if e.Type == KubeEventAdded {
		tenantReq := tenant.Tenant{Name: namespace.ObjectMeta.Name, ExternalID: string(namespace.ObjectMeta.UID)}
		tenantResp := tenant.Tenant{}
		glog.Infof("KubeEventAdded: Posting to /tenants: %+v", tenantReq)
		tenantUrl, err := l.restClient.GetServiceUrl("tenant")
		if err != nil {
			glog.Infof("KubeEventAdded:Error adding tenant %s: %+v", tenantReq.Name, err)
		} else {
			err := l.restClient.Post(fmt.Sprintf("%s/tenants", tenantUrl), tenantReq, &tenantResp)
			if err != nil {
				glog.Infof("KubeEventAdded: Error adding tenant %s: %+v", tenantReq.Name, err)
			} else {
				glog.Infof("KubeEventAdded: Added tenant: %+v", tenantResp)
			}
		}
	} else if e.Type == KubeEventDeleted {
		// TODO
	}

	// Ignore repeated events during namespace termination
	if namespace.Status.Phase == v1.NamespaceTerminating {
		if e.Type != KubeEventModified {
			handleAnnotations(namespace, l)
		}
	} else {
		handleAnnotations(namespace, l)
	}

}

// handleAnnotations on a namespace by implementing extra features requested through the annotation
func handleAnnotations(o *v1.Namespace, l *kubeListener) {
	glog.Infof("In handleAnnotations")

	// We only care about one annotation for now.
	CreateDefaultPolicy(o, l)
}

// CreateDefaultPolicy handles isolation flag on a namespace by creating/deleting
// default network policy.
func CreateDefaultPolicy(o *v1.Namespace, l *kubeListener) {
	glog.Infof("In CreateDefaultPolicy for %v\n", o)
	tenant, err := l.resolveTenantByName(o.ObjectMeta.Name)
	if err != nil {
		glog.Infof("In CreateDefaultPolicy :: Error :: failed to resolve tenant %s \n", err)
		return
	}

	policyName := fmt.Sprintf("ns%d", tenant.NetworkID)

	romanaPolicy := &common.Policy{
		Direction: common.PolicyDirectionIngress,
		Name:      policyName,
		AppliedTo: []common.Endpoint{{TenantNetworkID: &tenant.NetworkID}},
		Peers:     []common.Endpoint{{Peer: common.Wildcard}},
		Rules:     []common.Rule{{Protocol: common.Wildcard}},
	}

	glog.Infof("In CreateDefaultPolicy with policy %v\n", romanaPolicy)

	var desiredAction networkPolicyAction

	if np, ok := o.ObjectMeta.Annotations["net.beta.kubernetes.io/networkpolicy"]; ok {
		glog.Infof("Handling default policy on a namespace %s, policy is now %s \n", o.ObjectMeta.Name, np)
		policy := struct {
			Ingress struct {
				Isolation string `json:"isolation"`
			} `json:"ingress"`
		}{}
		err := json.NewDecoder(strings.NewReader(np)).Decode(&policy)
		if err != nil {
			glog.Infof("In CreateDefaultPolicy :: Error decoding network policy: %s", err)
			return
		}

		glog.Infoln("Decoded to policy:", policy)
		if policy.Ingress.Isolation == "DefaultDeny" {
			glog.Infoln("Isolation enabled")
			desiredAction = networkPolicyActionDelete
		} else {
			desiredAction = networkPolicyActionAdd
		}
	} else {
		glog.Infof("Handling default policy on a namespace, no annotation detected assuming non isolated namespace\n")
		desiredAction = networkPolicyActionAdd
	}

	if err2 := l.applyNetworkPolicy(desiredAction, *romanaPolicy); err2 != nil {
		glog.Infof("In CreateDefaultPolicy :: Error :: failed to apply %v to the policy %s \n", desiredAction, err2)
	}
}

// NsWatch is a generator that watches namespace related events in
// kubernetes API and publishes this events to a channel.
func (l *kubeListener) nsWatch(done <-chan struct{}, url string) (chan Event, error) {
	out := make(chan Event, l.namespaceBufferSize)

	// watcher watches all namespaces.
	watcher := cache.NewListWatchFromClient(
		l.kubeClient.CoreClient,
		"namespaces",
		api.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformer(
		watcher,
		&v1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				out <- Event{
					Type:   KubeEventAdded,
					Object: obj,
				}
			},
			UpdateFunc: func(old, obj interface{}) {
				out <- Event{
					Type:   KubeEventModified,
					Object: obj,
				}
			},
			DeleteFunc: func(obj interface{}) {
				out <- Event{
					Type:   KubeEventDeleted,
					Object: obj,
				}
			},
		})

	go controller.Run(done)

	return out, nil
}

// ProduceNewPolicyEvents produces kubernetes network policy events that arent applied
// in romana policy service yet.
func ProduceNewPolicyEvents(out chan Event, done <-chan struct{}, kubeListener *kubeListener) {
	var sleepTime time.Duration = 1
	glog.Infof("Listening for kubernetes network policies")

	// watcher watches all network policy.
	watcher := cache.NewListWatchFromClient(
		kubeListener.kubeClient.ExtensionsClient,
		"networkpolicies",
		api.NamespaceAll,
		fields.Everything(),
	)

	store, controller := cache.NewInformer(
		watcher,
		&v1beta1.NetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				out <- Event{
					Type:   KubeEventAdded,
					Object: obj,
				}
			},
			UpdateFunc: func(old, obj interface{}) {
				out <- Event{
					Type:   KubeEventModified,
					Object: obj,
				}
			},
			DeleteFunc: func(obj interface{}) {
				out <- Event{
					Type:   KubeEventDeleted,
					Object: obj,
				}
			},
		})

	go controller.Run(done)
	time.Sleep(sleepTime)

	var kubePolicyList []v1beta1.NetworkPolicy
	for _, kp := range store.List() {
		kubePolicyList = append(kubePolicyList, kp.(v1beta1.NetworkPolicy))
	}

	newEvents, oldPolicies, err := kubeListener.syncNetworkPolicies(kubePolicyList)
	if err != nil {
		glog.Errorf("Failed to sync romana policies with kube policies, sync failed with %s", err)
	}

	glog.Infof("Produce policies detected %d new kubernetes policies and %d old romana policies", len(newEvents), len(oldPolicies))

	// Create new kubernetes policies
	for en, _ := range newEvents {
		out <- newEvents[en]
	}

	// Delete old romana policies.
	// TODO find a way to remove policy deletion from this function. Stas.
	policyUrl, err := kubeListener.restClient.GetServiceUrl("policy")
	if err != nil {
		glog.Errorf("Failed to discover policy url before deleting outdated romana policies")
	}

	for k, _ := range oldPolicies {
		err = kubeListener.restClient.Delete(fmt.Sprintf("%s/policies/%d", policyUrl, oldPolicies[k].ID), nil, &oldPolicies)
		if err != nil {
			glog.Errorf("Sync policies detected obsolete policy %d but failed to delete, %s", oldPolicies[k].ID, err)
		}
	}
}

// httpGet is a wraps http.Get for the purpose of unit testing.
func httpGet(url string) (io.Reader, error) {
	resp, err := http.Get(url)
	return resp.Body, err
}

// watchKubernetesResource dependencies
var httpGetFunc = httpGet

// getAllPoliciesFunc wraps request to Policy for the purpose of unit testing.
func getAllPolicies(restClient *common.RestClient) ([]common.Policy, error) {
	policyUrl, err := restClient.GetServiceUrl("policy")
	if err != nil {
		return nil, err
	}

	policies := []common.Policy{}
	err = restClient.Get(policyUrl+"/policies", &policies)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

// Dependencies for syncNetworkPolicies
var getAllPoliciesFunc = getAllPolicies

// syncNetworkPolicies compares a list of kubernetes network policies with romana network policies,
// it returns a list of kubernetes policies that don't have corresponding kubernetes network policy for them,
// and a list of romana policies that used to represent kubernetes policy but corresponding kubernetes policy is gone.
func (l *kubeListener) syncNetworkPolicies(kubePolicies []v1beta1.NetworkPolicy) (kubernetesEvents []Event, romanaPolicies []common.Policy, err error) {
	glog.V(1).Infof("In syncNetworkPolicies with %v", kubePolicies)

	policies, err := getAllPoliciesFunc(l.restClient)
	if err != nil {
		return
	}

	glog.V(1).Infof("In syncNetworkPolicies fetched %d romana policies", len(policies))

	// Compare kubernetes policies and all romana policies by name.
	// TODO Coparing by name is fragile should be `external_id == UID`. Stas.

	// Prepare a list of kubernetes policies that don't have corresponding
	// romana policy.
	var found bool
	accountedRomanaPolicies := make(map[int]bool)

	for kn, kubePolicy := range kubePolicies {
		namespacePolicyNamePrefix := fmt.Sprintf("kube.default.")
		found = false
		for pn, policy := range policies {
			fullPolicyName := fmt.Sprintf("%s%s", namespacePolicyNamePrefix, kubePolicy.ObjectMeta.Name)
			if fullPolicyName == policy.Name {
				found = true
				accountedRomanaPolicies[pn] = true
				break
			}
		}

		if !found {
			glog.V(3).Infof("Sync policies detected new kube policy %v", kubePolicies[kn])
			kubernetesEvents = append(kubernetesEvents, Event{KubeEventAdded, kubePolicies[kn]})
		}
	}

	// Delete romana policies that don't have corresponding
	// kubernetes policy.
	// Ignore policies that don't have "kube." prefix in the name.
	for k, _ := range policies {
		if !strings.HasPrefix(policies[k].Name, "kube.") {
			glog.V(4).Infof("Sync policies skipping policy %s since it doesn't match the prefix `kube.`", policies[k].Name)
			continue
		}

		if !accountedRomanaPolicies[k] {
			glog.Infof("Sync policies detected that romana policy %d is obsolete - scheduling for deletion", policies[k].ID)
			glog.V(3).Infof("Sync policies detected that romana policy %d is obsolete - scheduling for deletion", policies[k].ID)
			romanaPolicies = append(romanaPolicies, policies[k])
		}
	}

	return
}
