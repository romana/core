// Copyright (c) 2017 Pani Networks Inc
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

package listener

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"

	"k8s.io/client-go/1.5/pkg/api"
	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/fields"
	"k8s.io/client-go/1.5/pkg/labels"
	"k8s.io/client-go/1.5/tools/cache"
)

type RomanaIP struct {
	Auto bool   `json:"auto"`
	IP   string `json:"ip"`
}

type ExternalIP struct {
	IP string `json:"ip" form:"ip"`
}

type ExposedIPSpec struct {
	RomanaIP      RomanaIP
	NodeIPAddress string
	Activated     bool
}

type ExposedIPSpecMap struct {
	sync.Mutex
	IPForService map[string]ExposedIPSpec
}

var (
	RomanaExposedIPSpecMap = ExposedIPSpecMap{IPForService: make(map[string]ExposedIPSpec)}
)

func (l *KubeListener) startRomanaIPSync(stop <-chan struct{}) {
	// serviceWatcher is a new ListWatch object created from the specified
	// CoreClientSet above for watching service events.
	serviceWatcher := cache.NewListWatchFromClient(
		l.kubeClient.CoreClient,
		"services",
		api.NamespaceAll,
		fields.Everything())

	// Setup a notifications for specific events using NewInformer.
	_, serviceInformer := cache.NewInformer(
		serviceWatcher,
		&v1.Service{},
		time.Duration(30)*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l.kubernetesAddServiceEventHandler,
			UpdateFunc: l.kubernetesUpdateServiceEventHandler,
			DeleteFunc: l.kubernetesDeleteServiceEventHandler,
		},
	)

	log.Println("Starting receving service events.")
	go serviceInformer.Run(stop)
}

// kubernetesAddServiceEventHandler is called when Kubernetes reports an
// add service event It connects to the Romana agent and adds the service
// external IP as RomanaIP to the Romana cluster.
func (l *KubeListener) kubernetesAddServiceEventHandler(n interface{}) {
	service, ok := n.(*v1.Service)
	if !ok {
		log.Printf("Error processing add event for service (%s) ", n)
		return
	}

	log.Printf("Add event received for service (%s) ", service.GetName())

	if err := l.updateRomanaIP(service); err != nil {
		log.Printf("Error updating romanaIP for service (%s): %s",
			service.Name, err)
		return
	}
}

// kubernetesUpdateServiceEventHandler is called when Kubernetes reports an
// update service event. It connects to the Romana agent and updates the service
// external IP as RomanaIP to the Romana cluster.
func (l *KubeListener) kubernetesUpdateServiceEventHandler(o, n interface{}) {
	service, ok := n.(*v1.Service)
	if !ok {
		log.Printf("Error processing update event for service (%s) ", n)
		return
	}

	log.Printf("Update Event received for service (%s) ", service.GetName())

	if err := l.updateRomanaIP(service); err != nil {
		log.Printf("Error updating romanaIP for service (%s): %s",
			service.Name, err)
		return
	}
}

// kubernetesDeleteServiceEventHandler is called when Kubernetes reports a
// delete service event. It connects to the Romana agent and deletes the
// RomanaIP from the Romana cluster.
func (l *KubeListener) kubernetesDeleteServiceEventHandler(n interface{}) {
	service, ok := n.(*v1.Service)
	if !ok {
		log.Printf("Error processing Delete Event received for service (%s) ", n)
		return
	}

	log.Printf("Delete event received for service (%s) ", service.GetName())

	l.deleteRomanaIP(service)
}

func (l *KubeListener) updateRomanaIP(service *v1.Service) error {
	RomanaExposedIPSpecMap.Lock()
	defer RomanaExposedIPSpecMap.Unlock()

	serviceName := service.GetName()

	annotation := service.GetAnnotations()
	romanaAnnotation, ok := annotation["romanaip"]
	if ok {
		_, foundService := RomanaExposedIPSpecMap.IPForService[serviceName]
		if foundService {
			fmt.Printf("Service (%s) already has romanaIP associated with it.",
				serviceName)
			return nil
		}

		var romanaIP RomanaIP
		err := json.Unmarshal([]byte(romanaAnnotation), &romanaIP)
		if err != nil {
			return fmt.Errorf("Error: romana annotation error: %s", err)
		}

		if net.ParseIP(romanaIP.IP) == nil {
			return errors.New("Error: romanaIP is not valid.")
		}

		updatedService := *service
		updatedService.Spec.ExternalIPs = []string{romanaIP.IP}
		_, err = l.kubeClient.CoreClient.Services(updatedService.GetNamespace()).Update(&updatedService)
		if err != nil {
			return fmt.Errorf("Error: externalIP couldn't be updated for service (%s): %s",
				serviceName, err)
		}

		pods, err := l.kubeClient.CoreClient.Endpoints(updatedService.GetNamespace()).List(
			api.ListOptions{
				LabelSelector: labels.SelectorFromSet(updatedService.GetLabels()),
			})
		if len(pods.Items) < 1 {
			return fmt.Errorf("Error: pod not found for service (%s)",
				serviceName)
		}
		if err != nil {
			return fmt.Errorf("Error: pod error for service (%s): %s",
				serviceName, err)
		}
		if !(len(pods.Items[0].Subsets) > 0 &&
			len(pods.Items[0].Subsets[0].Addresses) > 0) {
			return fmt.Errorf("Error: node address not found for service (%s)",
				serviceName)
		}

		// use first pod to get node address for now until we support ipam
		// for romanaIP allocations.
		node, err := l.kubeClient.CoreClient.Nodes().Get(*pods.Items[0].Subsets[0].Addresses[0].NodeName)
		if err != nil {
			return fmt.Errorf("Error: node not found for pod for service (%s): %s",
				serviceName, err)
		}

		if len(node.Status.Addresses) < 1 {
			return fmt.Errorf("Error: node address not found for node (%s)",
				node.Name)
		}

		exposedIPSpec := ExposedIPSpec{
			RomanaIP:      romanaIP,
			NodeIPAddress: node.Status.Addresses[0].Address,
			Activated:     true,
		}

		l.agentAddRomanaIP(exposedIPSpec)
		RomanaExposedIPSpecMap.IPForService[serviceName] = exposedIPSpec

		log.Tracef(trace.Private, "RomanaExposedIPSpecMap.IPForService: %v\n",
			RomanaExposedIPSpecMap.IPForService)

	}

	return nil
}

func (l *KubeListener) deleteRomanaIP(service *v1.Service) {
	RomanaExposedIPSpecMap.Lock()
	defer RomanaExposedIPSpecMap.Unlock()

	exposedIPSpec, ok := RomanaExposedIPSpecMap.IPForService[service.GetName()]
	if !ok {
		log.Printf("Error service not found in the list: %s", service.GetName())
		return
	}

	l.agentDeleteRomanaIP(exposedIPSpec)
	delete(RomanaExposedIPSpecMap.IPForService, service.GetName())

	log.Tracef(trace.Private, "RomanaExposedIPSpecMap.IPForService: %v\n",
		RomanaExposedIPSpecMap.IPForService)
}

func (l *KubeListener) agentDeleteRomanaIP(e ExposedIPSpec) {
	ip := ExternalIP{IP: e.RomanaIP.IP}
	agentURL := fmt.Sprintf("http://%s:9604/romanaip", e.NodeIPAddress)
	err := l.restClient.Delete(agentURL, ip, &ip)
	if err != nil {
		log.Errorf("Error in sending agent, externalIP (%s) deletion information",
			ip.IP)
	}
}

func (l *KubeListener) agentAddRomanaIP(e ExposedIPSpec) {
	ip := ExternalIP{IP: e.RomanaIP.IP}
	agentURL := fmt.Sprintf("http://%s:9604/romanaip", e.NodeIPAddress)
	err := l.restClient.Post(agentURL, ip, &ip)
	if err != nil {
		log.Errorf("Error in sending agent, externalIP (%s) addition information",
			ip.IP)
	}
}
