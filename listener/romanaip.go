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

	"github.com/romana/core/common/api"
	"github.com/romana/core/common/log/trace"

	log "github.com/romana/rlog"
	k8sapi "k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/fields"
	"k8s.io/client-go/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

type ExternalIP struct {
	IP string `json:"ip" form:"ip"`
}

type ExposedIPSpecMap struct {
	sync.Mutex
	IPForService map[string]api.ExposedIPSpec
}

var (
	RomanaExposedIPSpecMap = ExposedIPSpecMap{IPForService: make(map[string]api.ExposedIPSpec)}
)

func (l *KubeListener) startRomanaIPSync(stop <-chan struct{}) {
	// serviceWatcher is a new ListWatch object created from the specified
	// CoreClientSet above for watching service events.
	serviceWatcher := cache.NewListWatchFromClient(
		l.kubeClientSet.CoreV1Client.RESTClient(),
		"services",
		k8sapi.NamespaceAll,
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

	log.Println("Started receiving service events.")
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

		var romanaIP api.RomanaIP
		err := json.Unmarshal([]byte(romanaAnnotation), &romanaIP)
		if err != nil {
			return fmt.Errorf("romana annotation error: %s", err)
		}

		// TODO: implement auto cidr mode for romanaIPs
		if romanaIP.Auto {
			return errors.New("romanaIP auto cidr mode not supported in this release")
		}
		if net.ParseIP(romanaIP.IP) == nil {
			return errors.New("romanaIP is not valid")
		}

		pods, err := l.kubeClientSet.CoreV1Client.Endpoints(service.GetNamespace()).List(
			v1.ListOptions{
				LabelSelector: labels.FormatLabels(service.GetLabels()),
			})
		if len(pods.Items) < 1 {
			return fmt.Errorf("pod not found for service (%s)",
				serviceName)
		}
		if err != nil {
			return fmt.Errorf("pod error for service (%s): %s",
				serviceName, err)
		}
		if !(len(pods.Items[0].Subsets) > 0 &&
			len(pods.Items[0].Subsets[0].Addresses) > 0) {
			return fmt.Errorf("node address not found for service (%s)",
				serviceName)
		}

		// use first pod to get node address for now until we support ipam
		// for romanaIP allocations.
		node, err := l.kubeClientSet.CoreV1Client.Nodes().Get(*pods.Items[0].Subsets[0].Addresses[0].NodeName)
		if err != nil {
			return fmt.Errorf("node not found for pod for service (%s): %s",
				serviceName, err)
		}

		if len(node.Status.Addresses) < 1 {
			return fmt.Errorf("node address not found for node (%s)",
				node.Name)
		}

		updatedService := *service
		updatedService.Spec.ExternalIPs = []string{romanaIP.IP}
		namespace := updatedService.GetNamespace()
		if namespace == "" {
			namespace = "default"
		}
		_, err = l.kubeClientSet.CoreV1Client.Services(namespace).Update(&updatedService)
		if err != nil {
			return fmt.Errorf("externalIP couldn't be updated for service (%s): %s",
				serviceName, err)
		}

		exposedIPSpec := api.ExposedIPSpec{
			RomanaIP:      romanaIP,
			NodeIPAddress: node.Status.Addresses[0].Address,
			Activated:     true,
			Namespace:     namespace,
		}

		if err := l.client.AddRomanaIP(exposedIPSpec); err != nil {
			return fmt.Errorf("error adding romanaIP (%s) to romana kvstore",
				exposedIPSpec.RomanaIP.IP)
		}

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
		log.Printf("error, service not found in the list: %s", service.GetName())
		return
	}

	if err := l.client.DeleteRomanaIP(exposedIPSpec.RomanaIP.IP); err != nil {
		log.Errorf("error deleting romanaIP (%s) from romana kvstore",
			exposedIPSpec.RomanaIP.IP)
		return
	}

	delete(RomanaExposedIPSpecMap.IPForService, service.GetName())

	log.Tracef(trace.Private, "RomanaExposedIPSpecMap.IPForService: %v\n",
		RomanaExposedIPSpecMap.IPForService)
}
