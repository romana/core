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
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	selector = "podSelector"
)

// Done is an alias for empty struct, used to make broadcast channels
// for terminating goroutines.
type Done struct{}

// Event is a representation of a structure that we receive from kubernetes API.
type Event struct {
	Type   string     `json:"Type"`
	Object KubeObject `json:"object"`
}

const (
	KubeEventAdded    = "ADDED"
	KubeEventDeleted  = "DELETED"
	KubeEventModified = "MODIFIED"

	// Signal used to terminate all goroutines
	// if connection to k8s API is lost.
	// Does not carry a valid .Object field.
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

type PodSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

type FromEntry struct {
	Pods PodSelector `json:"podSelector"`
}

type Ingress struct {
	From    []FromEntry `json:"from"`
	ToPorts []ToPort    `json:"ports"`
}

type ToPort struct {
	Port     uint   `json:"port"`
	Protocol string `json:"protocol"`
}

// TODO need to find a way to use different specs for different resources.
type Spec struct {
	Ingress     []Ingress   `json:"ingress"`
	PodSelector PodSelector `json:"podSelector"`
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

// isNewRevision checks if given event has higher ResourceVersion then previous one.
func isNewRevision(e Event, l *kubeListener) bool {
	now, errt := strconv.ParseUint(e.Object.Metadata.ResourceVersion, 10, 64)
	if errt != nil {
		glog.Infof("WARNING ignoring event %v. Failed to parse resourceVersion of the .Object", e)

		return false
	}

	if last, ok := l.lastEventPerNamespace[e.Object.Metadata.Namespace]; ok {
		if now <= last {
			glog.Infof("WARNING ignoring event %v since current resourceVersion is %d", e, last)

			return false
		} else {
			l.lastEventPerNamespace[e.Object.Metadata.Namespace] = now

			return true
		}
	}

	l.lastEventPerNamespace[e.Object.Metadata.Namespace] = now

	return true
}

// handle kubernetes events according to their type.
func (e Event) handle(l *kubeListener) {
	glog.Infof("Processing %s request for %s", e.Type, e.Object.Metadata.Name)

	// This event doesn't have a valid .Object field.
	if e.Type == InternalEventDeleteAll {
		return
	}

	// Ignore the events that we procesed already.
	if !isNewRevision(e, l) {
		return
	}

	if e.Object.Kind == "NetworkPolicy" && e.Type != KubeEventModified {
		e.handleNetworkPolicyEvent(l)
	} else if e.Object.Kind == "Namespace" {
		e.handleNamespaceEvent(l)
	} else {
		glog.Infof("Received unindentified request %s for %s", e.Type, e.Object.Metadata.Name)
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

	// DEBUG
	policyList, kubePolicy, err := PTranslator.Kube2RomanaBulk([]KubeObject{e.Object})
	if err != nil {
		glog.Fatalf("Error translating %v - %s", e.Object, err)
	}
	if len(kubePolicy) > 0 {
		glog.Fatalf("Error translating policy %v, returned as kube policy", e.Object)
	}

	policy := policyList[0]
	//	policy, err := l.translateNetworkPolicy(&e.Object)
	if err == nil {
		j1, _ := json.Marshal(e)
		j2, _ := json.Marshal(policy)
		glog.Infof("handleNetworkPolicyEvent(): translated\n\t%s\n\tto\n\t%s", j1, j2)
		l.applyNetworkPolicy(action, policy)
	} else {
		glog.Infoln(err)
	}
}

// handleNamespaceEvent by creating or deleting romana tenants.
func (e Event) handleNamespaceEvent(l *kubeListener) {
	glog.Infof("KubeEvent: Processing namespace event == %v and phase %v", e.Type, e.Object.Status)

	if e.Type == KubeEventAdded {
		tenantReq := tenant.Tenant{Name: e.Object.Metadata.Name, ExternalID: e.Object.Metadata.Uid}
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
	glog.Infof("In handleAnnotations")

	if o.Kind != "Namespace" {
		glog.Infof("Error handling annotations on a namespace - object is not a namespace %s \n", o.Kind)
		return
	}

	CreateDefaultPolicy(o, l)
}

func CreateDefaultPolicy(o KubeObject, l *kubeListener) {
	glog.Infof("In CreateDefaultPolicy for %v\n", o)
	tenant, err := l.resolveTenantByName(o.Metadata.Name)
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

	if np, ok := o.Metadata.Annotations["net.beta.kubernetes.io/networkpolicy"]; ok {
		glog.Infof("Handling default policy on a namespace %s, policy is now %s \n", o.Metadata.Name, np)
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

// watchEvents maintains goroutine fired by NsWatch, restarts it in case HTTP GET times out.
func (l *kubeListener) watchEvents(done <-chan Done, url string, resp *http.Response, out chan Event) {
	glog.Infoln("kubeListener.watchEvents(): Received namespace related event from kubernetes")

	// Uncomment and use if needed for debugging.
	//	buf := new(bytes.Buffer)
	//	treader := io.TeeReader(resp.Body, buf)
	//	dec := json.NewDecoder(treader)

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
			log.Printf("kubeListener.watchEvents(): Decoded event %v, error %v", e, err)
			if err != nil {
				// If fail
				glog.Infof("Failed to decode message from connection %s due to %s\n. Attempting to re-establish", url, err)
				// Then stop all goroutines
				out <- Event{Type: InternalEventDeleteAll}

				// And try to re-establish HTTP connection
				resp, err2 := http.Get(url)
				if err2 != nil {
					glog.Infof("kubeListener.watchEvents(): Failed establish connection %s due to %s\n.", url, err)
				} else if err2 == nil {
					//					buf = new(bytes.Buffer)
					//					treader = io.TeeReader(resp.Body, buf)
					//					dec = json.NewDecoder(treader)
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
	out := make(chan Event, l.namespaceBufferSize)

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
	url, err := common.CleanURL(fmt.Sprintf("%s/%s/%s/%s/?%s", kubeListener.kubeURL, kubeListener.policyNotificationPathPrefix, ns.Metadata.Name, kubeListener.policyNotificationPathPostfix, HttpGetParamWatch))
	if err != nil {
		return err
	}
	glog.Infof("kubeListener.produce(): Launching producer to listen for policy notifications on namespace %s at URL %s ", ns.Metadata.Name, url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	log.Printf("kubeListener.produce(): Read from %s", url)
	go kubeListener.watchEvents(done, url, resp, out)

	return nil
}

// ProducePolicies produces kubernetes network policy events that arent applied
// in romana policy service yet.
func ProducePolicies(out chan Event, done <-chan Done, namespace string, kubeListener *kubeListener) {
	// >> loop goroutine start
	// >> 1. fire up watchKubernetesResource
	// >> 1.1 if watchKubernetesResource returns error, repeat with incremental delay
	// >> 2. compare policies returned from watchKubernetesResource
	// >> with policies registered with romana policy service.
	// >> see syncNetworkPolicies, pass events received from syncNetworkPolicies
	// >> into the out channel
	// >> >> loop select
	// >> >> 3. if event is received on channel from watchKubernetesResource
	// >> >> pass it into the out channel
	// >> >> 4. if channel from watchKubernetesResource is closed, repeat from 1
	// >> >> 5. if done channel closed then return
	// << << loop select end
	// << loop goroutine end

	var sleepTime time.Duration = 1
	url := fmt.Sprintf("%s/%s/%s/%s", kubeListener.kubeURL, kubeListener.policyNotificationPathPrefix, namespace, kubeListener.policyNotificationPathPostfix)
	glog.Infof("Listening for kubernetes network policy events for namespace %s on %s", namespace, url)
	for {
		items, in, err := kubeListener.watchKubernetesResource(url, done)
		if err != nil {
			glog.Infof("Failed to create listener for kubernetes network policies on %s, repeat in %d seconds", namespace, sleepTime)
			glog.V(1).Infof("Failed to create listener for kubernetes network policies on %s, error %s", namespace, err)
			time.Sleep(sleepTime * time.Second)
			sleepTime += 1
			continue
		}

		// TODO should be syncNetworkPolicies instead
		for _, policy := range items {
			genEvent := Event{KubeEventAdded, policy}
			glog.V(2).Infof("New policy event generated to account for difference between romana policy and kubernetes %v", genEvent)
			out <- genEvent
		}

	Loop:
		for {
			select {
			case <-done:
				glog.V(2).Infof("Shutting down listener for %s", namespace)
				return
			case e, ok := <-in:
				if ok {
					glog.V(4).Infof("New kubernetes network policy event on %s", namespace)
					out <- e
				} else {
					glog.V(4).Infof("Connection to %s terminated", namespace)
					glog.V(5).Infof("Connection to %s terminated - error %v", url, e)
					break Loop
				}
			}
		}
	}
}

// watchKubernetesResource retrieves a list of kubernetes objects
// associated with particular resource and channel of events.
func (l *kubeListener) watchKubernetesResource(url string, done <-chan Done) ([]KubeObject, <-chan Event, error) {
	// 1. list current objects in a resource
	// curl -s http://192.168.99.10:8080/apis/extensions/v1beta1/namespaces/http-tests/networkpolicies
	// 1.1 if error then return
	// 1.2 store resourceVersion from request in 1
	// 1.3 store objects found in a resource
	// curl -s http://192.168.99.10:8080/apis/extensions/v1beta1/namespaces/http-tests/networkpolicies | jq -r '.metadata.resourceVersion'
	// 2. subscribe for events starting from resourceVersion acquired in 1.1
	// curl -s "http://192.168.99.10:8080/apis/extensions/v1beta1/namespaces/http-tests/networkpolicies/?watch=true&resourceVersion=100"
	// 2.1 make json decoder for events
	// 2.1 make out channel
	// >> loop goroutine start
	// >> 3. decode event
	// >> 3.1 Check for errors
	// >> 3.2 if error code 410 then log, close out channel and return
	// {"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"too old resource version: 100 (7520)","reason":"Gone","code":410}}
	// >> 3.3 if error then log, close out channel and return
	// >> 3.6 if channel Done is closed while watching resource, close events channel and return
	// << loop goroutine end
	// 3. Return out channel and a items

	cleanUrl, err := common.CleanURL(url)
	if err != nil {
		glog.Errorf("In watchKubernetesResource failed to clean url %s", err)
		return nil, nil, err
	}

	resp, err := http.Get(cleanUrl)
	if err != nil {
		glog.Errorf("In watchKubernetesResource failed to GET response from kubernetes %s", err)
		return nil, nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("In watchKubernetesResource failed to read kubernetes response %s", err)
		return nil, nil, err
	}

	var kubeResource KubernetesResource
	err = json.Unmarshal(body, &kubeResource)
	if err != nil {
		glog.Errorf("In watchKubernetesResource failed to decode kubernetes response %s", err)
		// return nil, nil, err
	}

	glog.V(3).Infof("List of resources on %s returned %d items and resource version %s", url, len(kubeResource.Items), kubeResource.Metadata.ResourceVersion)

	watchUrl := fmt.Sprintf("%s?%s&%s=%s", url, HttpGetParamWatch, HttpGetParamResourceVersion, kubeResource.Metadata.ResourceVersion)
	watchResp, err := http.Get(watchUrl)
	if err != nil {
		glog.Infof("In watchKubernetesResource failed connect to %s due to %s", watchResp, err)
		return nil, nil, err
	}

	dec := json.NewDecoder(watchResp.Body)
	out := make(chan Event, l.namespaceBufferSize)

	var e Event

	go func() {
		glog.V(3).Infof("Watching for events on %s", watchUrl, kubeResource.Metadata.ResourceVersion)
		defer close(out)

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
					glog.Errorf("Failed to decode message from connection %s due to %s\n. Attempting to re-establish", watchUrl, err)
					// stop all goroutines
					// TODO - is this needed ?
					// out <- Event{Type: InternalEventDeleteAll}

					return
				} else if e.Type == "ERROR" {
					glog.Errorf("Received error from kubernetes %s while listening on %s", err, watchUrl)
					return
				} else {
					// Else submit event
					glog.V(3).Infof("Received event from kubernetes %v while listening on %s", e, watchUrl)
					out <- e
				}
			}

		}
	}()

	return kubeResource.Items, out, nil

}

// syncNetworkPolicies compares
func (l *kubeListener) syncNetworkPolicies(namespace string, kubePolicies []KubeObject, romanaPolicies []interface{}) ([]Event, error) {
	// 2.1 produce DELETE network policy events for outdated policies
	// in romana policy service
	// 2.2 produce ADDED network policy events for polices that arent
	// registered with romana policy service
	return nil, nil
}

type KubernetesResource struct {
	Kind     string       `json:"kind"`
	Metadata Metadata     `json:"metadata"`
	Items    []KubeObject `json:"items"`
}
