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
	"net/http"
	"strings"
	"time"

	"github.com/romana/core/common"
	romanaApi "github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"

	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/fields"
	"k8s.io/client-go/tools/cache"
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
			log.Errorf("Error adding policy with Kubernetes ID %s: %s", createPolicyList[pn].ID, err)
		}
	}

	// Delete old policies.
	for _, policy := range deleteEvents {
		// policy name is derived as below in translator and thus use the
		// same technique to derive the policy name here for deleting it.
		policyID := getPolicyID(policy)
		ok, err := l.client.DeletePolicy(policyID)
		if err != nil {
			log.Errorf("Error deleting policy %s: %s", policyID, err)
		}
		if !ok {
			log.Tracef(4, "can't delete policy %s, not found", policyID)
		}

	}
}

// TODO: see GetTenantIDFromNamespaceName
func GetTenantIDFromNamespaceObject(ns *v1.Namespace) string {
	return ns.GetName()
}

// TODO
// 1. we need this because policies have namespace names.
// For now we can have the name be the ID, but ideally it would be
// name and ID. We could cache ID-name mapping on namespace creation
// events, and get them all during startup, but is it possible for
// events to happen: 1. namespace created, 2. policy created,
// 3. namespace deleted, and us to receive them as 1,3,2 ?
//
// 2. This is used by CNI plugin so maybe this can go into
// something common to both listener & CNI plugin? move this into
// romana/core/kubernetes/helpers.go and move cni and listener
// under that romana/core/kubernetes too?
func GetTenantIDFromNamespaceName(nsName string) string {
	return nsName
}

// handleNamespaceEvent by creating or deleting romana tenants.
func handleNamespaceEvent(e Event, l *KubeListener) {
	namespace, ok := e.Object.(*v1.Namespace)
	if !ok {
		panic("Failed to cast namespace in handleNamespaceEvent")
	}

	log.Infof("KubeEvent: Processing namespace event == %v and phase %v", e.Type, namespace.Status)

	if e.Type == KubeEventAdded {
		// Noop for now, as we do not need to create tenants explicitly now
		// But see comment to GetTenantIDFromNamespaceName() above --
		// leaving this code path for if we want to use this for caching
		// ns ID-name correspondence
	} else if e.Type == KubeEventDeleted {
		log.Infof("KubeEventDeleted: deleting default policy for namespace %s (%s)", namespace.GetName(), namespace.GetUID())
		deleteDefaultPolicy(namespace, l)
		return
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

// getPolicyID generates a policyID based on the
func getPolicyID(kubePolicy v1beta1.NetworkPolicy) string {
	return fmt.Sprintf("kube.%s.%s.%s", kubePolicy.ObjectMeta.Namespace, kubePolicy.ObjectMeta.Name, string(kubePolicy.GetUID()))
}

// getDefaultPolicyID creates unique string to serve as ID
// for the default policy.However, Kubernetes does have a notion
// of namespace isolation, to which we correspond this policy, and
// so we construct a "synthetic"  ID with an _AllowAllPods2Talk_
// prefix followed by the namespace's Name.
func getDefaultPolicyID(o *v1.Namespace) string {
	// TODO this should be ExternalID, not Name...
	return fmt.Sprintf("AllowAllPods2Talk_%s_", o.GetUID())
}

// deleteDefaultPolicy deletes the policy, thus enabling isolation
// effectively setting DefaultDeny to on.
func deleteDefaultPolicy(o *v1.Namespace, l *KubeListener) {
	var err error
	// TODO this should be ExternalID, not Name...
	policyID := getDefaultPolicyID(o)

	ok, err := l.client.DeletePolicy(policyID)
	if err != nil {
		log.Errorf("In deleteDefaultPolicy :: Error :: failed to delete policy %s: %s\n", policyID, err)
	}
	if !ok {
		log.Tracef(4, "can't delete policy %s, not found", policyID)
	}
}

// addDefaultPolicy adds the default policy which is to allow
// all ingres.
func addDefaultPolicy(o *v1.Namespace, l *KubeListener) {
	var err error
	// Find tenant, to properly set up policy
	// TODO This really should be by external ID...
	tenantID := GetTenantIDFromNamespaceObject(o)
	policyID := getDefaultPolicyID(o)
	romanaPolicy := &romanaApi.Policy{
		ID:        policyID,
		Direction: romanaApi.PolicyDirectionIngress,
		AppliedTo: []romanaApi.Endpoint{{TenantID: tenantID}},
		Ingress: []romanaApi.RomanaIngress{
			romanaApi.RomanaIngress{
				Peers: []romanaApi.Endpoint{{Peer: romanaApi.Wildcard}},
				Rules: []romanaApi.Rule{{Protocol: romanaApi.Wildcard}},
			},
		},
	}

	err = l.addNetworkPolicy(*romanaPolicy)
	switch err := err.(type) {
	default:
		log.Errorf("In addDefaultPolicy :: Error :: failed to create policy  %s: %s\n", policyID, err)
	case nil:
		log.Debugf("In addDefaultPolicy: Succesfully created policy  %s\n", policyID)
	case common.HttpError:
		if err.StatusCode == http.StatusConflict {
			log.Infof("In addDefaultPolicy ::Policy %s already exists.\n", policyID)
		} else {
			log.Errorf("In addDefaultPolicy :: Error :: failed to create policy %s: %s\n", policyID, err)
		}
	}
}

// NsWatch is a generator that watches namespace related events in
// kubernetes API and publishes this events to a channel.
func (l *KubeListener) nsWatch(done <-chan struct{}) (chan Event, error) {
	out := make(chan Event, l.namespaceBufferSize)

	// watcher watches all namespaces.
	watcher := cache.NewListWatchFromClient(
		l.kubeClientSet.CoreV1Client.RESTClient(),
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
		KubeListener.kubeClientSet.ExtensionsV1beta1Client.RESTClient(),
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

	for k, _ := range oldPolicies {
		ok, err := KubeListener.client.DeletePolicy(oldPolicies[k].ID)
		if err != nil {
			log.Errorf("Sync policies detected obsolete policy %s but failed to delete, %s", oldPolicies[k].ID, err)
		}
		if !ok {
			log.Tracef(4, "can't delete policy %s, not found", oldPolicies[k].ID)
		}
	}
}

// getAllPoliciesFunc wraps request to Policy for the purpose of unit testing.
func getAllPolicies(client *client.Client) ([]romanaApi.Policy, error) {
	return client.ListPolicies()
}

// Dependencies for syncNetworkPolicies
var getAllPoliciesFunc = getAllPolicies

// syncNetworkPolicies compares a list of kubernetes network policies with romana network policies,
// it returns a list of kubernetes policies that don't have corresponding kubernetes network policy for them,
// and a list of romana policies that used to represent kubernetes policy but corresponding kubernetes policy is gone.
func (l *KubeListener) syncNetworkPolicies(kubePolicies []v1beta1.NetworkPolicy) (kubernetesEvents []Event, romanaPolicies []romanaApi.Policy, err error) {
	log.Infof("In syncNetworkPolicies with %v", kubePolicies)

	policies, err := getAllPoliciesFunc(l.client)
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
		// TODO this seems like a bug - that's not how default policy is named elsewhere - GG
		// kube.default is only referenced in test. This should be a const anyway.
		namespacePolicyIDPrefix := "kube.default."
		found = false
		for pn, policy := range policies {
			fullPolicyID := fmt.Sprintf("%s%s", namespacePolicyIDPrefix, kubePolicy.GetName())
			if fullPolicyID == policy.ID {
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
		if !strings.HasPrefix(policies[k].ID, "kube.") {
			log.Tracef(trace.Inside, "Sync policies skipping policy %s since it doesn't match the prefix `kube.`", policies[k].ID)
			continue
		}

		if !accountedRomanaPolicies[k] {
			log.Infof("Sync policies detected that romana policy %s is obsolete - scheduling for deletion", policies[k].ID)
			log.Tracef(trace.Inside, "Sync policies detected that romana policy %s is obsolete - scheduling for deletion", policies[k].ID)
			romanaPolicies = append(romanaPolicies, policies[k])
		}
	}

	return
}
