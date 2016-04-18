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
	"log"
	"net/http"
)

const (
	urlPostfix = "api/v1/namespaces/?watch=true"
	selector = "podSelector"
)

// Done is an alias for empty struct, used to make broadcast channels
// for terminating goroutines.
type done struct{}

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

// getSelector extracts selector value from KubeObject.
func (o KubeObject) getSelector(config Config) string {
	var selector string
	// TODO this should use Config.Resource.Selector path instead of podSelector.
	for k, v := range o.Spec.PodSelector {
		selector = k + "=" + v + "#"
	}
	return selector
}

type PodSelector map[string]string

type FromEntry struct {
	Pods PodSelector `json:"pods"`
}

type AllowIncoming  struct {
	From []FromEntry `json:"from"`
	ToPorts []ToPort `json:"toPorts"`
}


type ToPort struct {
	Port uint64 `json:"port"`
	Protocol string `json:"protocol"`
}

// TODO need to find a way to use different specs for different resources.
type Spec struct {
	AllowIncoming AllowIncoming`json:"allowIncoming"`
	PodSelector   PodSelector     `json:"podSelector"`
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
}

// watchEvents maintains goroutine fired by NsWatch, restarts it in case HTTP GET times out.
func (l *kubeListener) watchEvents(done <-chan Done, url string, resp *http.Response, out chan Event) {
	if config.Server.Debug {
		log.Println("Received namespace related event from kubernetes", resp.Body)
	}

	dec := json.NewDecoder(resp.Body)
	var e Event

	for {
		select {
		case <-done:
			return
		default:
			// Attempting to read event from HTTP connection
			err := dec.Decode(&e)
			if err != nil {
				// If fail
				if config.Server.Debug {
					log.Printf("Failed to decode message from connection %s due to %s\n. Attempting to re-establish", url, err)
				}
				// Then stop all goroutines
				out <- Event{Type: InternalEventDeleteAll}

				// And try to re-establish HTTP connection
				resp, err2 := http.Get(url)
				if (err2 != nil) && (config.Server.Debug) {
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
func nsWatch(done <-chan Done, url string, kubeListener *kubeListener Config) (<-chan Event, error) {
	out := make(chan Event)

	resp, err := http.Get(url)
	if err != nil {
		return out, err
	}

	go l.watchEvents(done, url, resp, out)

	return out, nil
}

// Produce method listens for resource updates happening within givcen namespace
// and publishes this updates in a channel
func (ns KubeObject) produce(out chan Event, done <-chan Done, kubeListener *kubeListener) error {
	url := fmt.Sprintf("%s/%s/%s/%s", config.Api.Url, l.UrlPrefix, ns.Metadata.Name, urlPostfix)
	if config.Server.Debug {
		log.Println("Launching producer to listen on ", url)
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	go l.watchEvents(done, url, resp, out)

	return nil
}
