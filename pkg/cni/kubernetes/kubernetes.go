// Copyright (c) 2017 Pani Networks
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

// Package has structures for CNI plugin to interact with Kubernetes.
package kubernetes

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/types"
	log "github.com/romana/rlog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"net"
)

type PodDescription struct {
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
}

// K8sArgs is the valid CNI_ARGS used for Kubernetes
type K8sArgs struct {
	types.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}

func (k8s K8sArgs) MakePodName() string {
	const suffixLength = 8
	var suffix string
	infra := string(k8s.K8S_POD_INFRA_CONTAINER_ID)
	if len(infra) > suffixLength {
		suffix = infra[:suffixLength]
	} else {
		suffix = infra
	}

	return fmt.Sprintf("%s.%s.%s", k8s.K8S_POD_NAME, k8s.K8S_POD_NAMESPACE, suffix)
}

func (k8s K8sArgs) MakeVethName() string {
	const suffixLength = 8
	const vethPrefix = "romana"
	var suffix string
	infra := string(k8s.K8S_POD_INFRA_CONTAINER_ID)
	if len(infra) > suffixLength {
		suffix = infra[:suffixLength]
	} else {
		suffix = infra
	}

	return fmt.Sprintf("%s-%s", vethPrefix, suffix)
}

func GetPodDescription(args K8sArgs, configFile string) (*PodDescription, error) {
	// Init kubernetes client. Attempt to load from statically configured k8s config or fallback on in-cluster
	kubeClientConfig, err := clientcmd.BuildConfigFromFlags("", configFile)
	if err != nil {
		return nil, err
	}
	log.Debugf("Created kube config err=(%s)", err)
	kubeClient, err := kubernetes.NewForConfig(kubeClientConfig)
	log.Debugf("Created kube client err=(%s)", err)

	pod, err := kubeClient.Core().Pods(string(args.K8S_POD_NAMESPACE)).Get(fmt.Sprintf("%s", args.K8S_POD_NAME))
	if err != nil {
		log.Errorf("Failed to discover a pod %s, err=(%s)", args.K8S_POD_NAME, err)
		return nil, err
	}
	log.Debugf("Discovered a pod %v", pod)

	res := PodDescription{
		Name:        args.MakePodName(),
		Namespace:   string(args.K8S_POD_NAMESPACE),
		Labels:      pod.Labels,
		Annotations: pod.Annotations,
	}

	return &res, nil
}
