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
	"log"
)

// manageResources manages map of termination channels and fires up new
// per-namespace goroutines when needed.
func (l *kubeListener) manageResources(ns Event, terminators map[string]chan Done, out chan Event) {
	uid := ns.Object.Metadata.Uid
	log.Printf("kubeListener: manageResources(): Received event %s", ns.Type)
	if ns.Type == KubeEventAdded {
		log.Printf("kubeListener: manageResources(): ADDED event for %s", uid)

		if _, ok := terminators[uid]; ok {
			log.Printf("kubeListener: manageResources(): Received ADDED event for uid that is already known, ignoring ", uid)
			return
		}
		done := make(chan Done)
		terminators[uid] = done
		ns.Object.produce(out, terminators[uid], l)
	} else if ns.Type == KubeEventDeleted {
		if _, ok := terminators[uid]; !ok {
			log.Printf("kubeListener: manageResources(): Received DELETED event for uid that is not known, ignoring ", uid)
			return
		}
		log.Printf("kubeListener: manageResources(): DELETED event for %s", uid)

		// Send shutdown signal to the goroutine that handles given namespace.
		close(terminators[uid])

		// Delete termination channel for the namespace.
		delete(terminators, uid)

		// Delete resource version counter for the namespace.
		delete(l.lastEventPerNamespace, uid)

	} else if ns.Type == InternalEventDeleteAll {
		// Terminate all per-namespace goroutines
		// clean associated resources.
		for uid, c := range terminators {
			close(c)
			delete(terminators, uid)
			delete(l.lastEventPerNamespace, uid)
		}
	} else {
		log.Printf("kubeListener: manageResources(): Unknown event.")
	}
}

// conductor manages a set of goroutines one per namespace.
func (l *kubeListener) conductor(in <-chan Event, done <-chan Done) <-chan Event {
	// done in arguments is a channel that can be used to stop Conductor itsefl
	// while map of Done's below is for terminating managed gorotines.

	// Idea of this map is to keep termination channels organized
	// so when DELETED event occurs on a namespace it would be possible
	// to terminater related goroutine.
	terminators := map[string]chan Done{}

	ns := Event{}
	out := make(chan Event, l.namespaceBufferSize)
	log.Printf("kubeListener: conductor(): entered with in: %v, done: %v", in, done)
	go func() {
		for {
			select {
			case ns = <-in:
				log.Printf("kubeListener: conductor(): calling manageResources")
				l.manageResources(ns, terminators, out)
				// ADDED, DELETED events for namespace handled here
				log.Printf("kubeListener: conductor(): calling handle on %+v", ns)
				ns.handle(l)
			case <-done:
				log.Printf("kubeListener: conductor(): got done on %v", done)
				return
			}
		}
	}()

	return out
}
