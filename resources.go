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
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"log"
	"net/http"
)

const (
	selector = "podSelector"
)

// Done is an alias for empty struct, used to make broadcast channels
// for terminating goroutines.
type Done struct{}

/*
{"type":"ADDED","object":{"kind":"Namespace","apiVersion":"v1","metadata":{"name":"default","selfLink":"/api/v1/namespaces/default","uid":"d10db271-dc03-11e5-9c86-0213e1312dc5","resourceVersion":"6","creationTimestamp":"2016-02-25T21:07:45Z"},"spec":{"finalizers":["kubernetes"]},"status":{"phase":"Active"}}}
*/

// Event is a representation of a structure that we receive from kubernetes API.
type Event struct {
	Type   string     `json:"Type"`
	Object KubeObject `json:"object"`
}

const (
	KubeEventAdded         = "ADDED"
	KubeEventDeleted       = "DELETED"
	KubeEventModified      = "MODIFIED"
	InternalEventDeleteAll = "_DELETE_ALL"
)

// KubeObject is a representation of object in kubernetes.
type KubeObject struct {
	Kind       string            `json:"kind"`
	Spec       Spec              `json:"spec"`
	ApiVersion string            `json:"apiVersion"`
	Metadata   Metadata          `json:"metadata"`
	Status     map[string]string `json:"status,omitempty"`
}

// makeId makes id to identify kube object.
func (o KubeObject) makeId() string {
	id := o.Metadata.Name + "/" + o.Metadata.Namespace
	return id
}

type PodSelector map[string]string

type FromEntry struct {
	Pods PodSelector `json:"pods"`
}

type AllowIncoming struct {
	From    []FromEntry `json:"from"`
	ToPorts []ToPort    `json:"toPorts"`
}

type ToPort struct {
	Port     uint   `json:"port"`
	Protocol string `json:"protocol"`
}

// TODO need to find a way to use different specs for different resources.
type Spec struct {
	AllowIncoming AllowIncoming `json:"allowIncoming"`
	PodSelector   PodSelector   `json:"podSelector"`
}

// Metadata is a representation of metadata in kubernetes object
type Metadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	SelfLink          string            `json:"selfLink"`
	Uid               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

// handle kubernetes events according to their type.
func (e Event) handle(l *kubeListener) {
	log.Printf("Processing %s request for %s", e.Type, e.Object.Metadata.Name)

	if e.Object.Kind == "NetworkPolicy" && e.Type != KubeEventModified {
		e.handleNetworkPolicyEvent(l)
	} else if e.Object.Kind == "Namespace" {
		e.handleNamespaceEvent(l)
	} else {
		log.Printf("Received unindentified request %s for %s", e.Type, e.Object.Metadata.Name)
	}
}

// handleNetworkPolicyEvent by creating or deleting romana policies.
func (e Event) handleNetworkPolicyEvent(l *kubeListener) {
	var action networkPolicyAction
	if e.Type == KubeEventAdded {
		action = networkPolicyActionAdd
	} else {
		action = networkPolicyActionDelete
	}
	policy, err := l.translateNetworkPolicy(&e.Object)
	if err == nil {
		l.applyNetworkPolicy(action, policy)
	} else {
		log.Println(err)
	}
}

// handleNamespaceEvent by creating or deleting romana tenants.
func (e Event) handleNamespaceEvent(l *kubeListener) {
	log.Printf("Processing namespace event == %v and phase %v", e.Type, e.Object.Status)

	if e.Type == KubeEventAdded {
		tenantReq := tenant.Tenant{Name: e.Object.Metadata.Name, ExternalID: e.Object.Metadata.Name}
		tenantResp := tenant.Tenant{}
		log.Printf("processor: Posting to /tenants: %#v", tenantReq)
		tenantUrl, err := l.restClient.GetServiceUrl("tenant")
		if err != nil {
			log.Printf("Error adding tenant %s: %#v", tenantReq.Name, err)
		} else {
			err := l.restClient.Post(fmt.Sprintf("%s/tenants", tenantUrl), tenantReq, &tenantResp)
			if err != nil {
				log.Printf("Error adding tenant %s: %#v", tenantReq.Name, err)
			} else {
				log.Printf("Added tenant: %#v", tenantResp)
			}
		}
	} else {
		// TODO finish once UUID is merged
		// tenantReq := tenant.Tenant{Name: e.Object.Metadata.Name}
		// tenantResp := tenant.Tenant{}
		// err = client.Delete("/tenants", tenantReq, &tenantResp)
		// if err != nil {
		// 	log.Printf("Error adding tenant %s: %#v", tenantReq.Name, err)
		// } else {
		// 	log.Printf("Added tenant: %#v", tenantResp)
		// }
	}

	// Ignore repeated events during namespace termination
	if e.Object.Status["phase"] == "Terminating" {
		if e.Type != KubeEventModified {
			e.Object.handleAnnotations(l)
		}
	} else {
		e.Object.handleAnnotations(l)
	}

}

// handleAnnotations on a namespace by implementing extra features requested through the annotation
func (o KubeObject) handleAnnotations(l *kubeListener) {
	log.Printf("In handleAnnotations")

	if o.Kind != "Namespace" {
		log.Printf("Error handling annotations on a namespace - object is not a namespace %s \n", o.Kind)
		return
	}

	CreateDefaultPolicy(o, l)
}

func CreateDefaultPolicy(o KubeObject, l *kubeListener) {
	log.Printf("In CreateDefaultPolicy for %v\n", o)
	tenant, _, err := l.resolveTenantByName(o.Metadata.Name)
	if err != nil {
		log.Printf("In CreateDefaultPolicy :: Error :: failed to resolve tenant %s \n", err)
	}

	policyName := fmt.Sprintf("ns%d", tenant.ID)

	romanaPolicy := &common.Policy{
		Direction: common.PolicyDirectionIngress,
		Name:      policyName,
		AppliedTo: []common.Endpoint{{TenantNetworkID: tenant.ID}},
		Peers:     []common.Endpoint{{Peer: "any"}},
		Rules:     []common.Rule{{Protocol: "any"}},
	}

	log.Printf("In CreateDefaultPolicy with policy %v\n", romanaPolicy)

	var desiredAction networkPolicyAction

	if isolation, ok := o.Metadata.Annotations["net.alpha.kubernetes.io/network-isolation"]; ok {
		log.Printf("Handling default policy on a namespace %s, isolation is now %s \n", o.Metadata.Name, isolation)
		switch isolation {
		case "on":
			desiredAction = networkPolicyActionAdd
		case "off":
			desiredAction = networkPolicyActionDelete
		default:
			log.Printf("In CreateDefaultPolicy :: Error :: unrecognised annotation on a namespace %s is %s (expected on|off) \n",
				o.Metadata.Name, isolation)
			return
		}

	} else {
		log.Printf("Handling default policy on a namespace, no annotation detected assuming non isolated namespace\n")
		desiredAction = networkPolicyActionAdd
	}

	if err2 := l.applyNetworkPolicy(desiredAction, *romanaPolicy); err2 != nil {
		log.Printf("In CreateDefaultPolicy :: Error :: failed to apply %v to the policy %s \n", desiredAction, err)
	}
}

// watchEvents maintains goroutine fired by NsWatch, restarts it in case HTTP GET times out.
func (l *kubeListener) watchEvents(done <-chan Done, url string, resp *http.Response, out chan Event) {
	log.Println("Received namespace related event from kubernetes", resp.Body)

	dec := json.NewDecoder(resp.Body)
	var e Event

	for {
		select {
		case <-done:
			return
		default:
			// Flush e to ensure nothing gets carried over
			e = Event{}

			// Attempting to read event from HTTP connection
			err := dec.Decode(&e)
			if err != nil {
				// If fail
				log.Printf("Failed to decode message from connection %s due to %s\n. Attempting to re-establish", url, err)
				// Then stop all goroutines
				out <- Event{Type: InternalEventDeleteAll}

				// And try to re-establish HTTP connection
				resp, err2 := http.Get(url)
				if err2 != nil {
					log.Printf("Failed establish connection %s due to %s\n.", url, err)
				} else if err2 == nil {
					dec = json.NewDecoder(resp.Body)
				}
			} else {
				// Else submit event
				out <- e
			}
		}

	}
}

// NsWatch is a generator that watches namespace related events in
// kubernetes API and publishes this events to a channel.
func (l *kubeListener) nsWatch(done <-chan Done, url string) (<-chan Event, error) {
	out := make(chan Event)

	resp, err := http.Get(url)
	if err != nil {
		return out, err
	}

	go l.watchEvents(done, url, resp, out)

	return out, nil
}

// Produce method listens for resource updates happening within given namespace
// and publishes these updates in a channel.
func (ns KubeObject) produce(out chan Event, done <-chan Done, kubeListener *kubeListener) error {
	url, err := common.CleanURL(fmt.Sprintf("%s/%s/%s%s", kubeListener.kubeUrl, kubeListener.policyNotificationPathPrefix, ns.Metadata.Name, kubeListener.policyNotificationPathPostfix))
	if err != nil {
		return err
	}
	log.Printf("Launching producer to listen for policy notifications on namespace %s at URL %s ", ns.Metadata.Name, url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	go kubeListener.watchEvents(done, url, resp, out)

	return nil
}
