// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package listener listens to Kubernetes for policy updates.
package listener

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"

	log "github.com/romana/rlog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultSegmentLabelName = "romana.io/segment"
	defaultTenantLabelName  = "namespace"
	defaultSyncIntervalStr  = "30s"
	initialSyncDuration     = 60 * time.Second
	initialSyncInterval     = 10 * time.Millisecond
	defaultNodeAttributes   = "spec.unschedulable"
)

// KubeListener is a Service that listens to updates
// from Kubernetes by connecting to the endpoints specified
// and consuming chunked JSON documents. The endpoints are
// constructed from kubeURL and the following paths:
// 1. namespaceNotificationPath for namespace additions/deletions
// 2. policyNotificationPathPrefix + <namespace name> + policyNotificationPathPostfix
//    for policy additions/deletions.
type KubeListener struct {
	Addr   string
	client *client.Client

	segmentLabelName    string
	tenantLabelName     string
	namespaceBufferSize uint64

	kubeClientSet *kubernetes.Clientset

	// Maintains state about what things have been synchronized.
	// A mutex is required because of watchers emitting events in
	// separate goroutines
	sync.RWMutex
	policiesSynced bool

	nodeStore    cache.Store
	nodeInformer *cache.Controller

	// This is intended to lock for the purposes of changing
	// syncNodesRunning flag. See documentation for syncNodes() for the rest.
	syncNodesMutex       sync.Locker
	syncNodesRunning     bool
	syncNodesTicker      *time.Ticker
	syncNodesInterval    time.Duration
	initialNodesSyncDone bool
	nodeAttributes       []string

	// romanaExposedIPSpecMap stores romana VIP mapping information.
	romanaExposedIPSpecMap ExposedIPSpecMap
}

// Routes returns various routes used in the service.
func (l *KubeListener) Routes() common.Routes {
	routes := common.Routes{}
	return routes
}

func (l *KubeListener) GetAddress() string {
	return l.Addr
}

// Name implements method of Service interface.
func (l *KubeListener) Name() string {
	return "kubernetesListener"
}

func (l *KubeListener) loadConfig() error {
	var err error
	configPrefix := "/kubelistener/config/"

	l.segmentLabelName, err = l.client.Store.GetString(configPrefix+"segmentLabelName", defaultSegmentLabelName)
	if err != nil {
		return err
	}

	l.tenantLabelName, err = l.client.Store.GetString(configPrefix+"tenantLabelName", defaultTenantLabelName)
	if err != nil {
		return err
	}

	var syncInterval string
	syncInterval, err = l.client.Store.GetString(configPrefix+"syncInterval", defaultSyncIntervalStr)
	if err != nil {
		return err
	}
	l.syncNodesInterval, err = time.ParseDuration(syncInterval)
	if err != nil {
		return err
	}

	var nodeAttrStr string
	nodeAttrStr, err = l.client.Store.GetString(configPrefix+"nodeAttributes", defaultNodeAttributes)
	if err != nil {
		return err
	}
	l.nodeAttributes = strings.Split(nodeAttrStr, ",")

	if err := l.kubeClientInit(); err != nil {
		return fmt.Errorf("Error while loading kubernetes client %s", err)
	}

	return nil
}

// TODO there should be a better way to introduce translator
// then global variable like this one.
var PTranslator Translator

// addNetworkPolicy adds the policy to the policy service.
func (l *KubeListener) addNetworkPolicy(policy api.Policy) error {
	return l.client.AddPolicy(policy)
}

func (l *KubeListener) Initialize(clientConfig common.Config) error {
	var err error
	l.syncNodesMutex = &sync.Mutex{}
	l.client, err = client.NewClient(&clientConfig)
	if err != nil {
		return err
	}
	err = l.loadConfig()
	if err != nil {
		return err
	}
	// TODO, find a better place to initialize
	// the translator. Stas.
	PTranslator.Init(l.client, l.segmentLabelName, l.tenantLabelName)
	tc := PTranslator.GetClient()
	if tc == nil {
		log.Critical("Failed to initialize rest client for policy translator.")
		os.Exit(255)
	}

	// Channel for stopping watching kubernetes events.
	done := make(chan struct{})

	// l.ProcessNodeEvents listens and processes kubernetes node events,
	// mainly allowing nodes to be added/removed to/from romana cluster
	// based on these events.
	l.ProcessNodeEvents(done)

	log.Infof("%s: Starting server", l.Name())
	eventc, err := l.nsWatch(done)
	if err != nil {
		log.Critical("Namespace watcher failed to start", err)
		os.Exit(255)
	}

	l.process(eventc, done)

	ProduceNewPolicyEvents(eventc, done, l)

	l.romanaExposedIPSpecMap = ExposedIPSpecMap{IPForService: make(map[string]api.ExposedIPSpec)}
	l.startRomanaVIPSync(done)

	log.Info("All routines started")
	return nil
}
