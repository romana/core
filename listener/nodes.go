// Copyright (c) 2016-2017 Pani Networks Inc
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

// Package listener's nodes.go contains a subset of listener functionality
// where it connects to kubernetes using kubernetes client-go and watches
// node creation/deletion events and then adds/deletes the nodes
// to/from romana cluster appropriately.
package listener

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"time"

	log "github.com/romana/rlog"

	romanaApi "github.com/romana/core/common/api"
	romanaErrors "github.com/romana/core/common/api/errors"

	"github.com/romana/core/common/log/trace"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/fields"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func (l *KubeListener) kubeClientInit() error {
	var err error

	// Try generating config for kubernetes client-go from
	// in-cluster variables like KUBERNETES_SERVICE_HOST, etc
	// so that we can connect to kubernetes using them.
	kConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("error: %s", err)
	}

	// Get a set of REST clients which connect to kubernetes services
	// from the config generated above.
	l.kubeClientSet, err = kubernetes.NewForConfig(kConfig)
	if err != nil {
		return fmt.Errorf("error while connecting to kubernetes: %s", err)
	}

	return nil
}

// nodeToHost converts a K8S node object to Romana host object.
func (l *KubeListener) nodeToHost(n interface{}) (romanaApi.Host, error) {
	var node *v1.Node
	var ok bool
	host := romanaApi.Host{}

	if node, ok = n.(*v1.Node); !ok {
		return host, fmt.Errorf("Expected node object, got %s: %T", n, n)
	}
	if node.Name == "" || node.Status.Addresses == nil || len(node.Status.Addresses) == 0 {
		return host, fmt.Errorf("Received invalid node name or IP Address: (%#v)", node)
	}
	host.Name = node.Name
	hostIP := net.ParseIP(node.Status.Addresses[0].Address)
	if hostIP == nil {
		return host, fmt.Errorf("Cannot parse address of node %s: %s", node.Name, node.Status.Addresses[0].Address)
	}
	host.IP = hostIP
	host.Tags = node.GetLabels()

	return host, nil
}

// syncNodes checks what nodes are defined in K8S cluster vs
// hosts defined in Romana and synchronizes them.
// In case syncNodes() is called multiple
// times, it would lock here, check the status of syncNodesRunning flag
// and bail out if there is another instance of syncNodes() running.
// Note that that can only happen when the syncNodes() routine was taking
// so long that the next scheduled one has started, which is unlikely,
// but it doesn't hurt to ensure that they don't step on each other.
// Note also that individual handlers (on node add/delete/update) will not
// synchronize -- in the worst case, they will fail and be picked up by next
// synchronization.
func (l *KubeListener) syncNodes() {
	log.Trace(trace.Inside, "Entering syncNodes()\n")

	var err error
	l.syncNodesMutex.Lock()
	if l.syncNodesRunning {
		// This really can only happen if syncNodes was taking too long
		// and the next scheduled syncNodes started. Very unlikely, but
		// doesn'thurt to check.
		log.Infof("syncNodes() already running, will exit.")
		l.syncNodesMutex.Unlock()
		return
	}
	l.syncNodesRunning = true
	l.syncNodesMutex.Unlock()

	k8sNodesList := l.nodeStore.List()

	romanaHostList := l.client.IPAM.ListHosts()
	log.Debugf("Comparing Romana host list %d vs K8S node list %d", len(k8sNodesList), len(romanaHostList.Hosts))

	var nodeInRomana bool
	var romanaHost romanaApi.Host
	var hostToAdd romanaApi.Host

	for _, n := range k8sNodesList {
		if hostToAdd, err = l.nodeToHost(n); err != nil {
			log.Error(err)
			continue
		}

		log.Tracef(trace.Inside, "Checking if node %s is in Romana", hostToAdd)

		nodeInRomana = false
		// This is not super-efficient but as we don't have that many hosts for now
		// to deal with, it can do.
		for _, romanaHost = range romanaHostList.Hosts {
			if romanaHost.IP.String() == hostToAdd.IP.String() {
				nodeInRomana = true
				break
			}
		}
		if !nodeInRomana {
			log.Tracef(trace.Inside, "Trying to add host %s to Romana", hostToAdd)
			if err = l.romanaHostAdd(hostToAdd); err != nil {
				log.Error(err)
			}
		}
	}

	var hostToRemove romanaApi.Host
	var hostInK8S bool

	var node *v1.Node
	for _, romanaHost = range romanaHostList.Hosts {
		hostInK8S = false
		for _, n := range k8sNodesList {
			node = n.(*v1.Node)
			if hostToRemove, err = l.nodeToHost(node); err != nil {
				log.Error(err)
				continue
			}
			if hostToRemove.IP.String() == romanaHost.IP.String() {
				hostInK8S = true
				break
			}
		}
		log.Tracef(trace.Inside, "Checking if host %s is in K8S: %t", romanaHost, hostInK8S)

		if !hostInK8S {
			if err = l.romanaHostRemove(hostToRemove); err != nil {
				log.Error(err)
			}
		}
	}
	l.syncNodesMutex.Lock()
	l.syncNodesRunning = false
	l.syncNodesMutex.Unlock()
}

// ProcessNodeEvents processes kubernetes node events, there by
// adding/deleting nodes to/from romana cluster automatically
// when they are added/removed to/from kubernetes cluster.
func (l *KubeListener) ProcessNodeEvents(done <-chan struct{}) {
	log.Debug("In ProcessNodeEvents()")

	// nodeWatcher is a new ListWatch object created from the specified
	// kubeClientSet which k8s.io/client-go exports for watching node events.
	nodeWatcher := cache.NewListWatchFromClient(
		l.kubeClientSet.CoreV1Client.RESTClient(),
		"nodes",
		api.NamespaceAll,
		fields.Everything())

	// Setup a notifications for specific events using NewInformer.
	l.nodeStore, l.nodeInformer = cache.NewInformer(
		nodeWatcher,
		&v1.Node{},
		// TODO this can also be configurable
		time.Minute,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l.kubernetesAddNodeEventHandler,
			UpdateFunc: l.kubernetesUpdateNodeEventHandler,
			DeleteFunc: l.kubernetesDeleteNodeEventHandler,
		},
	)

	log.Infof("Starting receving node events.")
	go l.nodeInformer.Run(done)

	log.Infof("Starting sync ticker with %s", l.syncNodesInterval)
	l.syncNodesTicker = time.NewTicker(l.syncNodesInterval)

	log.Infof("Starting initial sync ticker with %s", initialSyncInterval)
	initialSyncTicker := time.NewTicker(initialSyncInterval)
	log.Infof("Setting timeout for initial sync ticker to %s from now", initialSyncDuration)
	initialSyncTimeout := time.After(initialSyncDuration)

INITIAL_SYNC:
	for {
		select {
		case <-initialSyncTicker.C:
			if l.nodeInformer.HasSynced() {
				log.Info("Initial synchronization completed\n")
				l.initialNodesSyncDone = true
				initialSyncTicker.Stop()
				l.syncNodes()
				break INITIAL_SYNC
			}
		case <-initialSyncTimeout:
			log.Errorf("Timeout after %s while synchronizing nodes\n", initialSyncDuration)
			os.Exit(1)

		}
	}

	go func() {
		for {
			select {
			case t := <-l.syncNodesTicker.C:
				if !l.initialNodesSyncDone {
					continue
				}
				log.Tracef(trace.Inside, "Entering timed syncNodes() at %s\n", t)
				l.syncNodes()
			}
		}
	}()

}

// kubernetesAddNodeEventHandler is called when Kubernetes reports an
// add node event.
func (l *KubeListener) kubernetesAddNodeEventHandler(n interface{}) {
	if !l.initialNodesSyncDone {
		log.Debug("Initial synchronization not completed, ignoring add event")
		return
	}
	if hostToAdd, err := l.nodeToHost(n); err != nil {
		log.Errorf("Error handling node add event: %s", err)
	} else if err = l.romanaHostAdd(hostToAdd); err != nil {
		log.Errorf("Error handling node add event: %s", err)
	}
}

// kubernetesDeleteNodeEventHandler is called when Kubernetes reports a
// delete node event.
func (l *KubeListener) kubernetesDeleteNodeEventHandler(n interface{}) {
	if !l.initialNodesSyncDone {
		log.Debug("Initial synchronization not completed, ignoring delete event")
		return
	}
	if hostToRemove, err := l.nodeToHost(n); err != nil {
		log.Errorf("Error handling node remove event: %s", err)
	} else if err = l.romanaHostRemove(hostToRemove); err != nil {
		log.Errorf("Error handling node remove event: %s", err)
	}
}

// kubernetesUpdateNodeEventHandler is called when Kubernetes reports an
// update node event. It calls syncNodes to sync romana/kubernetes
// host list.
func (l *KubeListener) kubernetesUpdateNodeEventHandler(o, n interface{}) {
	if !l.initialNodesSyncDone {
		log.Debug("Initial synchronization not completed, ignoring update	 event")
		return
	}
	node, ok := n.(*v1.Node)
	if !ok {
		log.Errorf("Expected Node object, received (%T: %s)", n, n)
		return
	}
	oldNode, ok := o.(*v1.Node)
	if !ok {
		log.Errorf("Expected Node object, received (%T: %s)", o, o)
		return
	}

	host, err := l.nodeToHost(node)
	if err != nil {
		log.Errorf("Cannot update node %s: %s", node.Name, err)
		return
	}

	// There is only one reason for now to deal with this case: when labels change
	if !reflect.DeepEqual(oldNode.GetLabels(), node.GetLabels()) {
		log.Tracef(trace.Inside, "Update Node event received for %s: labels change from %v to %v", node.Name, oldNode.GetLabels(), node.GetLabels())
		err = l.client.IPAM.UpdateHostLabels(host)
		if err != nil {
			log.Errorf("Cannot update node %s: %s", node.Name, err)
		}
	}
}

// romanaHostAdd connects to romana API and adds a node to
// the romana cluster.
func (l *KubeListener) romanaHostAdd(host romanaApi.Host) error {
	var ok bool
	err := l.client.IPAM.AddHost(host)
	if _, ok = err.(romanaErrors.RomanaExistsError); ok {
		log.Infof("Host %s already exists, ignoring addition.", host)
		return nil
	} else if err == nil {
		log.Infof("Host (%s) successfully added to Romana cluster.", host)
		return nil
	}
	return err
}

// romanaHostRemove connects to romana API and removes a node from
// the romana cluster.
func (l *KubeListener) romanaHostRemove(host romanaApi.Host) error {
	err := l.client.IPAM.RemoveHost(host)
	if _, ok := err.(romanaErrors.RomanaNotFoundError); ok {
		log.Infof("Host %s is not found, ignoring removal", host)
		return nil
	} else if err == nil {
		log.Infof("Host %s successfully removed from Romana cluster", host)
		return nil
	}
	return err
}
