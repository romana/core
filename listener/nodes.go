// Copyright (c) 2016 Pani Networks Inc
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
	"errors"
	"fmt"
	"net"
	"time"

	log "github.com/romana/rlog"

	romanaApi "github.com/romana/core/common/api"

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
		return fmt.Errorf("Error: %s", err)
	}

	// Get a set of REST clients which connect to kubernetes services
	// from the config generated above.
	l.kubeClientSet, err = kubernetes.NewForConfig(kConfig)
	if err != nil {
		return fmt.Errorf("Error while connecting to kubernetes: %s", err)
	}

	return nil
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
	_, nodeInformer := cache.NewInformer(
		nodeWatcher,
		&v1.Node{},
		time.Minute,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l.kubernetesAddNodeEventHandler,
			UpdateFunc: l.kubernetesUpdateNodeEventHandler,
			DeleteFunc: l.kubernetesDeleteNodeEventHandler,
		},
	)

	log.Infof("Starting receving node events.")
	go nodeInformer.Run(done)
}

// kubernetesAddNodeEventHandler is called when Kubernetes reports an
// add-node event It connects to the Romana REST API and adds the node
// to the Romana cluster.
func (l *KubeListener) kubernetesAddNodeEventHandler(n interface{}) {
	log.Debug("In kubernetesAddNodeEventHandler()")
	node, ok := n.(*v1.Node)
	if !ok {
		log.Errorf("Error processing Add Event received for node(%s) ", n)
		return
	}

	log.Debugf("Add Event received for node(%s, %s, %d) ",
		node.Name, node.Status.Addresses, len(node.Status.Addresses))

	if err := romanaHostAdd(l, node); err != nil {
		log.Errorf("Error processing Add Event received for node(%s): %s",
			node.Name, err)
		return
	}

	log.Infof("Node (%s) successful added to romana cluster.", node.Name)
}

// kubernetesUpdateNodeEventHandler currently doesn't do anything yet.
// TODO: If node shows up with new IP or romana CIDR,
//       then accommodate it if possible.
func (l *KubeListener) kubernetesUpdateNodeEventHandler(o, n interface{}) {
	log.Debug("In kubernetesUpdateNodeEventHandler()")

	// node, ok := n.(*v1.Node)
	_, ok := n.(*v1.Node)
	if !ok {
		log.Errorf("Error processing Update Event received for node(%s) ", n)
		return
	}

	// Disable this for now, update events are sent every
	// 10 seconds per node, thus this could fill up the log
	// easily in very small amount of time.
	// log.Info("Update Event received for node: ",node.Name)
}

// kubernetesDeleteNodeEventHandler is called when Kubernetes reports a
// delete-node event It connects to the Romana REST API and deletes the
// node from the Romana cluster.
func (l *KubeListener) kubernetesDeleteNodeEventHandler(n interface{}) {
	log.Debug("In kubernetesDeleteNodeEventHandler()")
	node, ok := n.(*v1.Node)
	if !ok {
		log.Errorf("Error processing Delete Event received for node(%s) ", n)
		return
	}

	log.Debugf("Delete Event received for node(%s, %s) ",
		node.Name, node.Status.Addresses)

	if err := romanaHostRemove(l, node.Name); err != nil {
		log.Errorf("Error processing Delete Event received for node(%s): %v",
			node.Name, err)
		return
	}

	log.Infof("Node (%s) successful removed from romana cluster.", node.Name)
}

// romanaHostAdd connects to romana API and adds a node to
// the romana cluster.
func romanaHostAdd(l *KubeListener, node *v1.Node) error {
	if node.Name == "" || len(node.Status.Addresses) < 1 {
		log.Errorf("Error: received invalid host name or IP Address: (%s)", node)
		return errors.New("Error: received invalid host name or IP Address.")
	}
	hostname := node.Name
	hostIP := net.ParseIP(node.Status.Addresses[0].Address)
	log.Infof("KubeListener: Adding host IP: %s, Name: %s", hostIP, hostname)
	host := romanaApi.Host{IP: hostIP,
		Name: hostname,
		Tags: node.GetLabels(),
	}
	return l.client.IPAM.AddHost(host)
}

// romanaHostRemove connects to romana API and removes a node from
// the romana cluster.
func romanaHostRemove(l *KubeListener, node string) error {
	log.Infof("KubeListener: Removing host %s", node)
	if node == "" {
		log.Errorf("Error: received invalid node name (%s)", node)
		return errors.New("Error: received invalid node name.")
	}
	return l.client.IPAM.RemoveHost(romanaApi.Host{Name: node})
}
