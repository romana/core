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

// syncNodes checks what nodes are defined in K8S cluster vs
// hosts defined in Romana and synchronizes them.
func (l *KubeListener) syncNodes() {
	var err error
	l.Lock()
	defer l.Unlock()

	if !l.nodeStoreSynced {
		log.Debug("waiting for synchronization to complete")
		return
	}
	if time.Now().Before(l.syncNodesAfter) {
		log.Debugf("waiting until %v to execute sync", l.syncNodesAfter)
		return
	}
	l.syncNodesAfter = l.syncNodesAfter.Add(time.Minute)

	nodesIfc := l.nodeStore.List()
	var node *v1.Node
	var ok bool

	romanaHostList := l.client.IPAM.ListHosts()
	for _, nodeIfc := range nodesIfc {
		// This is not super-efficient but as we don't have that many hosts for now
		// to deal with, it can do.
		node, ok = nodeIfc.(*v1.Node)
		if !ok {
			log.Tracef(trace.Inside, "expected node object, got %#v", nodeIfc)
			continue
		}
		if node.Name == "" || node.Status.Addresses == nil || len(node.Status.Addresses) == 0 {
			log.Errorf("Received invalid node name or IP Address: (%#v)", node)
			continue
		}

		nodeInRomana := false
		for _, romanaHost := range romanaHostList.Hosts {
			if romanaHost.IP.String() == node.Status.Addresses[0].Address {
				nodeInRomana = true
				break
			}
		}
		if !nodeInRomana {
			ip := net.ParseIP(node.Status.Addresses[0].Address)
			if ip == nil {
				log.Errorf("Cannot parse node IP: %s", node.Status.Addresses[0].Address)
				continue
			}
			host := romanaApi.Host{IP: ip,
				Name: node.Name,
				Tags: node.GetLabels(),
			}
			err = l.client.IPAM.AddHost(host)
			if err == nil {
				log.Infof("Added host %s to Romana", host)
			} else {
				if _, ok := err.(romanaErrors.RomanaExistsError); ok {
					log.Infof("Host %s already exists, ignoring addition.", host)
				} else {
					log.Errorf("Error adding host %s to Romana: %s", host, err)
				}
			}
		}
	}

	for _, romanaHost := range romanaHostList.Hosts {
		hostInK8S := false
		for _, nodeIfc := range nodesIfc {
			node := nodeIfc.(*v1.Node)
			if romanaHost.IP.String() == node.Status.Addresses[0].Address {
				hostInK8S = true
				break
			}
		}
		if !hostInK8S {
			err = l.client.IPAM.RemoveHost(romanaHost)
			if err == nil {
				log.Infof("Removed host %s from Romana", romanaHost)
			} else {
				if _, ok := err.(romanaErrors.RomanaNotFoundError); ok {
					log.Infof("Host %s not found exists, ignoring removal.", romanaHost)
				} else {
					log.Errorf("Error removing host %s from Romana: %s", romanaHost, err)
				}
			}
		}
	}
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

	var nodeInformer *cache.Controller
	// Setup a notifications for specific events using NewInformer.
	l.nodeStore, nodeInformer = cache.NewInformer(
		nodeWatcher,
		&v1.Node{},
		time.Minute,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l.kubernetesNodeEventHandler,
			UpdateFunc: l.kubernetesUpdateNodeEventHandler,
			DeleteFunc: l.kubernetesNodeEventHandler,
		},
	)

	log.Infof("Starting receving node events.")

	go nodeInformer.Run(done)

	// Wait for the list of nodes to synchronize
	duration := 60 * time.Second
	timeout := time.After(duration)

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	log.Info("Waiting for node list to synchronize")
	for {
		select {
		case <-timeout:
			log.Errorf("timeout after %s while synchronizing nodes", duration)
			os.Exit(1)
		case <-ticker.C:
			if nodeInformer.HasSynced() {
				log.Info("node synchronization completed")
				l.Lock()
				l.nodeStoreSynced = true
				l.syncNodesAfter = time.Now()
				l.Unlock()
				l.syncNodes()
				return
			}
		}
	}
}

// kubernetesNodeEventHandler is called when Kubernetes reports an
// add/delete node event. It calls syncNodes to sync romana/kubernetes
// host list.
func (l *KubeListener) kubernetesNodeEventHandler(n interface{}) {
	log.Debug("In kubernetesNodeEventHandler()")
	_, ok := n.(*v1.Node)
	if !ok {
		log.Errorf("error processing node event received for node(%v)", n)
		return
	}

	l.RLock()
	ready := l.nodeStoreSynced
	l.RUnlock()
	if !ready {
		return
	}

	l.syncNodes()
}

// kubernetesUpdateNodeEventHandler is called when Kubernetes reports an
// update node event. It calls syncNodes to sync romana/kubernetes
// host list.
func (l *KubeListener) kubernetesUpdateNodeEventHandler(o, n interface{}) {
	log.Debug("In kubernetesUpdateNodeEventHandler()")

	_, ok := n.(*v1.Node)
	if !ok {
		log.Errorf("Error processing Update Event received for node(%s) ", n)
		return
	}

	l.RLock()
	ready := l.nodeStoreSynced
	l.RUnlock()
	if !ready {
		return
	}

	l.syncNodes()
}
