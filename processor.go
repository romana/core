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
	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"github.com/golang/glog"
	"time"
)

const (
	// TODO make a parameter. Stas.
	processorTickTime = 4
)

// Process is a goroutine that consumes resource update events and:
// 1. On receiving an added or deleted event:
//    a. If the Object Kind is NetworkPolicy, translates the body (Object of the event)
//       to romana policy (common.Policy) using translateNetworkPolicy, and then
//       calls applyNetworkPolicy with the appropriate action (add or delete)
//    b. If the Object Kind is Namespace, attempts to add a new Tenant to Romana with that name.
//       Logs an error if not possible.
// 2. On receiving a done event, exit the goroutine
func (l *kubeListener) process(in <-chan Event, done chan struct{}) {
	glog.Infof("kubeListener: process(): Entered with in %v, done %v", in, done)

	timer := time.Tick(processorTickTime * time.Second)
	var networkPolicyEvents []Event

	go func() {
		for {
			select {
			case <-timer:
				if len(networkPolicyEvents) > 0 {
					glog.V(1).Infof("Calling network policy handler for scheduled %d events", len(networkPolicyEvents))
					handleNetworkPolicyEvents(networkPolicyEvents, l)
					networkPolicyEvents = nil
				}
			case e := <-in:
				glog.V(1).Infof("kubeListener: process(): Got %v", e)
				switch obj := e.Object.(type) {
				case v1beta1.NetworkPolicy:
					glog.Infof("DEBUG scheduing network policy action, now scheduled %d actions", len(networkPolicyEvents))
					networkPolicyEvents = append(networkPolicyEvents, e)
				case v1.Namespace:
					handleNamespaceEvent(e, l)
//				case "":
//					glog.V(3).Infof("Processor received an event with empty Object.Kind field, ignoring")
				default:
					glog.Errorf("Processor received an event with unknown Object.Kind field %s, ignoring", obj)
				}
			case <-done:
				glog.Infof("kubeListener: process(): Got done")
				return
			}
		}
	}()
	return
}
