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

package listener

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	"github.com/romana/core/tenant"
	log "github.com/romana/rlog"

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
func handleNetworkPolicyEvents(events []Event, l *KubeListener) {
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
			log.Tracef(trace.Inside, "Ignoring %s event in handleNetworkPolicyEvents", event.Type)
		}
	}

	// Translate new network policies into romana policies.
	createPolicyList, kubePolicy, err := PTranslator.Kube2RomanaBulk(createEvents)
	if err != nil {
		log.Errorf("Not all kubernetes policies could be translated to Romana policies. Attempted %d, success %d, fail %d, error %s", len(createEvents), len(createPolicyList), len(kubePolicy), err)
	}
	for kn, _ := range kubePolicy {
		log.Errorf("Failed to translate kubernetes policy %v", kubePolicy[kn])
	}

	// Create new policies.
	for pn, _ := range createPolicyList {
		err = l.addNetworkPolicy(createPolicyList[pn])
		if err != nil {
			log.Errorf("Error adding policy with Kubernetes ID %s: %s", createPolicyList[pn].ExternalID, err)
		}
	}

	// Delete old policies.
	for _, policy := range deleteEvents {
		// TODO this must be changed to use External ID
		err = l.deleteNetworkPolicy(common.Policy{Name: policy.Name})
		if err != nil {
			log.Errorf("Error deleting policy %s (%s): %s", policy.Name, policy.GetUID(), err)
		}
	}
}

// handleNamespaceEvent by creating or deleting romana tenants.
func handleNamespaceEvent(e Event, l *KubeListener) {
	namespace, ok := e.Object.(*v1.Namespace)
	if !ok {
		panic("Failed to cast namespace in handleNamespaceEvent")
	}

	log.Infof("KubeEvent: Processing namespace event == %v and phase %v", e.Type, namespace.Status)

	if e.Type == KubeEventAdded {
		tenantReq := tenant.Tenant{Name: namespace.ObjectMeta.Name, ExternalID: string(namespace.ObjectMeta.UID)}
		tenantResp := tenant.Tenant{}
		log.Infof("KubeEventAdded: Posting to /tenants: %+v", tenantReq)
		tenantUrl, err := l.restClient.GetServiceUrl("tenant")
		if err != nil {
			log.Infof("KubeEventAdded:Error adding tenant %s: %+v", tenantReq.Name, err)
		} else {
			err := l.restClient.Post(fmt.Sprintf("%s/tenants", tenantUrl), tenantReq, &tenantResp)
			if err != nil {
				log.Infof("KubeEventAdded: Error adding tenant %s: %+v", tenantReq.Name, err)
			} else {
				log.Infof("KubeEventAdded: Added tenant: %+v", tenantResp)
			}
		}
	} else if e.Type == KubeEventDeleted {
		log.Infof("KubeEventDeleted: deleting default policy for namespace %s", namespace.GetUID())
		deleteDefaultPolicy(namespace, l)
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
func handleAnnotations(o *v1.Namespace, l *KubeListener) {
	log.Tracef(trace.Private, "In handleAnnotations")

	// We only care about one annotation for now.
	HandleDefaultPolicy(o, l)
}

// HandleDefaultPolicy handles isolation flag on a namespace by creating/deleting
// default network policy. See http://kubernetes.io/docs/user-guide/networkpolicies/
func HandleDefaultPolicy(o *v1.Namespace, l *KubeListener) {
	var defaultDeny bool
	annotationKey := "net.beta.kubernetes.io/networkpolicy"
	if np, ok := o.ObjectMeta.Annotations[annotationKey]; ok {
		log.Infof("Handling default policy on a namespace %s, policy is now %s \n", o.ObjectMeta.Name, np)
		// Annotations are stored in the Annotations map as raw JSON.
		// So we need to parse it.
		isolationPolicy := struct {
			Ingress struct {
				Isolation string `json:"isolation"`
			} `json:"ingress"`
		}{}
		// TODO change to json.Unmarshal. Stas
		err := json.NewDecoder(strings.NewReader(np)).Decode(&isolationPolicy)
		if err != nil {
			log.Errorf("In HandleDefaultPolicy :: Error decoding annotation %s: %s", annotationKey, err)
			return
		}
		log.Debugf("Decoded to policy: %v", isolationPolicy)
		defaultDeny = isolationPolicy.Ingress.Isolation == "DefaultDeny"
	} else {
		log.Infof("Handling default policy on a namespace, no annotation detected assuming non isolated namespace\n")
		defaultDeny = false
	}
	if defaultDeny {
		deleteDefaultPolicy(o, l)
	} else {
		addDefaultPolicy(o, l)
	}
}

// getDefaultPolicyName creates unique string to serve as ExternalID
// for the default policy. It is not strictly speaking an ExternalID
// as it does not have an exact equivalent as a policy ID in Kubernetes.
// However, Kubernetes does have a notion of namespace isolation, to which we
// correspond this policy, and so we construct a "synthetic" External ID
// with an _ISOLATION_ON_ prefix followed by the namespace's UID.
func getDefaultPolicyName(o *v1.Namespace) string {
	// TODO this should be ExternalID, not Name...
	return fmt.Sprintf("_AllowAll_%s", o.GetUID())
}

// deleteDefaultPolicy deletes the policy, thus enabling isolation
// effectively setting DefaultDeny to on.
func deleteDefaultPolicy(o *v1.Namespace, l *KubeListener) {
	var err error
	// TODO this should be ExternalID, not Name...
	policyName := getDefaultPolicyName(o)
	policy := common.Policy{Name: policyName}

	policyURL, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		log.Errorf("In deleteDefaultPolicy :: Failed to find policy service: %s\n", err)
		log.Errorf("In deleteDefaultPolicy :: Failed to delete default policy: %s\n", policyName)
		return
	}

	policyURL = fmt.Sprintf("%s/find/policies/%s", policyURL, policy.Name)
	err = l.restClient.Get(policyURL, &policy)
	if err != nil {
		// An annotation to set isolation on may be issued multiple times.
		// If it already was reacted to and default policy was dropped,
		// then we don't do anything.
		log.Debugf("In deleteDefaultPolicy :: Failed to find policy %s: %s, ignoring\n", policyName, err)
		return
	}
	if err = l.deleteNetworkPolicyByID(policy.ID); err != nil {
		log.Errorf("In deleteDefaultPolicy :: Error :: failed to delete policy %d: %s\n", policy.ID, err)
	}
}

// addDefaultPolicy adds the default policy which is to allow
// all ingres.
func addDefaultPolicy(o *v1.Namespace, l *KubeListener) {
	var err error
	// TODO this should be ExternalID, not Name...
	policyName := getDefaultPolicyName(o)

	// Before adding the default policy, see if it may already exist.
	policy := common.Policy{Name: policyName}

	policyURL, err := l.restClient.GetServiceUrl("policy")
	if err != nil {
		log.Errorf("In addDefaultPolicy :: Failed to find policy service: %s\n", err)
		log.Errorf("In addDefaultPolicy :: Failed to add default policy: %s\n", policyName)
		return
	}

	policyURL = fmt.Sprintf("%s/find/policies/%s", policyURL, policy.Name)
	err = l.restClient.Get(policyURL, &policy)
	if err == nil {
		// An annotation to set isolation off may be issued multiple
		// times and we already have the default policy caused by that in place.
		// So we just do not do anything.
		log.Infof("In addDefaultPolicy :: Policy %s (%d) already exists, ignoring\n", policy.Name, policy.ID)
		return
	}

	// Find tenant, to properly set up policy
	// TODO This really should be by external ID...
	tnt, err := l.resolveTenantByName(o.ObjectMeta.Name)
	if err != nil {
		log.Infof("In addDefaultPolicy :: Error :: failed to resolve tenant %s \n", err)
		return
	}

	romanaPolicy := &common.Policy{
		Direction: common.PolicyDirectionIngress,
		Name:      policyName,
		//		ExternalID: externalID,
		AppliedTo: []common.Endpoint{{TenantNetworkID: &tnt.NetworkID}},
		Ingress: []common.RomanaIngress{
			common.RomanaIngress{
				Peers: []common.Endpoint{{Peer: common.Wildcard}},
				Rules: []common.Rule{{Protocol: common.Wildcard}},
			},
		},
	}

	err = l.addNetworkPolicy(*romanaPolicy)
	switch err := err.(type) {
	default:
		log.Errorf("In addDefaultPolicy :: Error :: failed to create policy  %s: %s\n", policyName, err)
	case nil:
		log.Debugf("In addDefaultPolicy: Succesfully created policy  %s\n", policyName)
	case common.HttpError:
		if err.StatusCode == http.StatusConflict {
			log.Infof("In addDefaultPolicy ::Policy %s already exists.\n", policyName)
		} else {
			log.Errorf("In addDefaultPolicy :: Error :: failed to create policy %s: %s\n", policyName, err)
		}
	}
}

// NsWatch is a generator that watches namespace related events in
// kubernetes API and publishes this events to a channel.
func (l *KubeListener) nsWatch(done <-chan struct{}, url string) (chan Event, error) {
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
func ProduceNewPolicyEvents(out chan Event, done <-chan struct{}, KubeListener *KubeListener) {
	var sleepTime time.Duration = 1
	log.Infof("Listening for kubernetes network policies")

	// watcher watches all network policy.
	watcher := cache.NewListWatchFromClient(
		KubeListener.kubeClient.ExtensionsClient,
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

	newEvents, oldPolicies, err := KubeListener.syncNetworkPolicies(kubePolicyList)
	if err != nil {
		log.Errorf("Failed to sync romana policies with kube policies, sync failed with %s", err)
	}

	log.Infof("Produce policies detected %d new kubernetes policies and %d old romana policies", len(newEvents), len(oldPolicies))

	// Create new kubernetes policies
	for en, _ := range newEvents {
		out <- newEvents[en]
	}

	// Delete old romana policies.
	// TODO find a way to remove policy deletion from this function. Stas.
	policyUrl, err := KubeListener.restClient.GetServiceUrl("policy")
	if err != nil {
		log.Errorf("Failed to discover policy url before deleting outdated romana policies")
	}

	for k, _ := range oldPolicies {
		err = KubeListener.restClient.Delete(fmt.Sprintf("%s/policies/%d", policyUrl, oldPolicies[k].ID), nil, &oldPolicies)
		if err != nil {
			log.Errorf("Sync policies detected obsolete policy %d but failed to delete, %s", oldPolicies[k].ID, err)
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
func (l *KubeListener) syncNetworkPolicies(kubePolicies []v1beta1.NetworkPolicy) (kubernetesEvents []Event, romanaPolicies []common.Policy, err error) {
	log.Infof("In syncNetworkPolicies with %v", kubePolicies)

	policies, err := getAllPoliciesFunc(l.restClient)
	if err != nil {
		return
	}

	log.Infof("In syncNetworkPolicies fetched %d romana policies", len(policies))

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
			log.Tracef(trace.Inside, "Sync policies detected new kube policy %v", kubePolicies[kn])
			kubernetesEvents = append(kubernetesEvents, Event{KubeEventAdded, kubePolicies[kn]})
		}
	}

	// Delete romana policies that don't have corresponding
	// kubernetes policy.
	// Ignore policies that don't have "kube." prefix in the name.
	for k, _ := range policies {
		if !strings.HasPrefix(policies[k].Name, "kube.") {
			log.Tracef(trace.Inside, "Sync policies skipping policy %s since it doesn't match the prefix `kube.`", policies[k].Name)
			continue
		}

		if !accountedRomanaPolicies[k] {
			log.Infof("Sync policies detected that romana policy %d is obsolete - scheduling for deletion", policies[k].ID)
			log.Tracef(trace.Inside, "Sync policies detected that romana policy %d is obsolete - scheduling for deletion", policies[k].ID)
			romanaPolicies = append(romanaPolicies, policies[k])
		}
	}

	return
}
