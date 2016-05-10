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
	"github.com/romana/core/tenant"
	"log"
	"fmt"
)

/*
{"type":"ADDED","object":{"apiVersion":"romana.io/demo/v1","kind":"NetworkPolicy","metadata":{"name":"pol1","namespace":"default","selfLink":"/apis/romana.io/demo/v1/namespaces/default/networkpolicys/pol1","uid":"d7036130-e119-11e5-aab8-0213e1312dc5","resourceVersion":"119875","creationTimestamp":"2016-03-03T08:28:00Z","labels":{"owner":"t1"}},"spec":{"allowIncoming":{"from":[{"pods":{"tier":"frontend"}}],"toPorts":[{"port":80,"protocol":"TCP"}]},"podSelector":{"tier":"backend"}}}}
*/

// Process is a goroutine that consumes resource update events and:
// 1. On receiving an added or deleted event:
//    a. If the Object Kind is NetworkPolicy, translates the body (Object of the event)
//       to romana policy (common.Policy) using translateNetworkPolicy, and then
//       calls applyNetworkPolicy with the appropriate action (add or delete)
//    b. If the Object Kind is Namespace, attempts to add a new Tenant to Romana with that name.
//       Logs an error if not possible.
// 2. On receiving a done event, exit the goroutine
func (l *kubeListener) process(in <-chan Event, done chan Done) {
	go func() {
		for {
			select {
			case e := <-in:
				//				NPid := e.Object.makeId()
				if e.Type == KubeEventAdded || e.Type == KubeEventDeleted {
					log.Printf("Processing %s request for %s", e.Type, e.Object.Metadata.Name)
					if e.Object.Kind == "NetworkPolicy" {
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
					} else if e.Object.Kind == "Namespace" {
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
							//							tenantReq := tenant.Tenant{Name: e.Object.Metadata.Name}
							//							tenantResp := tenant.Tenant{}
							//							err = client.Delete("/tenants", tenantReq, &tenantResp)
							//							if err != nil {
							//								log.Printf("Error adding tenant %s: %#v", tenantReq.Name, err)
							//							} else {
							//								log.Printf("Added tenant: %#v", tenantResp)
							//							}
						}

					}
				}
				//				else {
				//					log.Printf("Received unindentified request %s for %s", e.Type, e.Object.Metadata.Name)
				//				}
			case <-done:
				return
			}
		}
	}()
	return
}
