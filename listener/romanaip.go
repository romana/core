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
	"os"
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

type ExposedIPSpecMap struct {
	sync.Mutex
	IPForService map[string]api.ExposedIPSpec
}

var (
	RomanaExposedIPSpecMap = ExposedIPSpecMap{IPForService: make(map[string]api.ExposedIPSpec)}
	serviceSyncTimer       = 60 * time.Second
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
	serviceStore, serviceInformer := cache.NewInformer(
		serviceWatcher,
		&v1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l.kubernetesAddServiceEventHandler,
			UpdateFunc: l.kubernetesUpdateServiceEventHandler,
			DeleteFunc: l.kubernetesDeleteServiceEventHandler,
		},
	)

	log.Println("Started receiving service events.")
	go serviceInformer.Run(stop)

	// Wait for the list of services to synchronize
	duration := 60 * time.Second
	timeout := time.After(duration)

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	log.Info("waiting for service list to synchronize")
	for {
		select {
		case <-timeout:
			log.Errorf("timeout after %s while synchronizing services", duration)
			os.Exit(1)
		case <-ticker.C:
			if serviceInformer.HasSynced() {
				go l.startRomanaIPPeriodicSync(stop, serviceStore)
				return
			}
		case <-stop:
			log.Info("received stop request from listener")
			return
		}
	}
}

func (l *KubeListener) startRomanaIPPeriodicSync(stop <-chan struct{}, serviceStore cache.Store) {
	serviceSyncTicker := time.NewTicker(serviceSyncTimer)
	var romanaIPPeriodicSyncMutex sync.Mutex

	for {
		select {
		case <-serviceSyncTicker.C:
			romanaIPPeriodicSyncMutex.Lock()

			l.syncRomanaIPs(serviceStore)
			l.syncExposedIPs()

			romanaIPPeriodicSyncMutex.Unlock()
		case <-stop:
			log.Info("received stop request from listener")
			return
		}
	}
}

func (l *KubeListener) syncRomanaIPs(serviceStore cache.Store) {
	serviceListAll := serviceStore.List()
	romanaIPMap := make(map[string]api.ExposedIPSpec)
	serviceMap := make(map[string]v1.Service)

	for i := range serviceListAll {
		service, serviceName, exposedIPSpec, err := l.extractServiceDetails(serviceListAll[i])
		if err != nil {
			log.Debugf("error fetching service details: %s", err)
			continue
		}

		romanaIPMap[serviceName] = *exposedIPSpec
		serviceMap[serviceName] = *service
	}

	// if no service with romanaIP annotation is found, skip
	// syncing, since there is nothing to be done here.
	if len(romanaIPMap) == 0 {
		return
	}

	RomanaExposedIPSpecMap.Lock()

	// update/add new services which we see
	for serviceName, rip := range romanaIPMap {
		eip, ok := RomanaExposedIPSpecMap.IPForService[serviceName]

		if ok && eip.RomanaIP.IP == rip.RomanaIP.IP &&
			eip.NodeIPAddress == rip.NodeIPAddress {
			// romanaIP is present, and match the current romanaIP
			// configuration, so nothing to be done here.
			continue
		}

		// update service locally for external IP
		updatedService := serviceMap[serviceName]
		updatedService.Spec.ExternalIPs = []string{rip.RomanaIP.IP}
		namespace := updatedService.GetNamespace()
		if namespace == "" {
			namespace = "default"
		}
		_, err := l.kubeClientSet.CoreV1Client.Services(namespace).Update(&updatedService)
		if err != nil {
			log.Errorf("externalIP couldn't be updated for service (%s): %s",
				serviceName, err)
			continue
		}

		// everything seems fine and addition/updating romanaIP was
		// a success and thus add the romanaIP to the exposedIP map here.
		RomanaExposedIPSpecMap.IPForService[serviceName] = rip
	}

	// remove old services not seen anymore in service list.
	for serviceName := range RomanaExposedIPSpecMap.IPForService {
		_, ok := romanaIPMap[serviceName]
		if ok {
			// service is present, so nothing to be done here.
			continue
		}

		// service was removed, so lets remove the details about it here
		delete(RomanaExposedIPSpecMap.IPForService, serviceName)
	}

	RomanaExposedIPSpecMap.Unlock()
}

func (l *KubeListener) syncExposedIPs() {
	RomanaExposedIPSpecMap.Lock()
	defer RomanaExposedIPSpecMap.Unlock()

	exposedIPMap, err := l.client.ListRomanaIPs()
	if err != nil {
		return
	}

	for serviceName, rip := range RomanaExposedIPSpecMap.IPForService {
		eip, ok := exposedIPMap[serviceName]

		if ok && eip.RomanaIP.IP == rip.RomanaIP.IP &&
			eip.NodeIPAddress == rip.NodeIPAddress {
			// romanaIP is present, and match the current romanaIP
			// configuration, so nothing to be done here.
			continue
		}

		// if this is romanaIP update, then lets remove it first
		if ok && (eip.RomanaIP.IP != rip.RomanaIP.IP ||
			eip.NodeIPAddress != rip.NodeIPAddress) {
			if err := l.client.DeleteRomanaIP(serviceName); err != nil {
				// log the error and then do nothing here since
				// even if deleting fails, it could be that the
				// service didn't exists,  the addition happens
				// below. so it should be ok to continue below
				// here.
				log.Debugf("error updating romanaIP (%s:%s) for service (%s) on node (%s:%s)",
					eip.RomanaIP.IP, rip.RomanaIP.IP, serviceName,
					eip.NodeIPAddress, rip.NodeIPAddress)
			}
		}

		// add to kvstore so that agent adds
		// appropriate external IP on node
		if err := l.client.AddRomanaIP(serviceName, rip); err != nil {
			log.Errorf("error adding romanaIP (%s) to romana kvstore",
				rip.RomanaIP.IP)
			continue
		}
	}

	// remove old services not seen anymore in service list.
	for serviceName, eip := range exposedIPMap {
		_, ok := RomanaExposedIPSpecMap.IPForService[serviceName]
		if ok {
			// service is present, so nothing to be done here.
			continue
		}

		// service was removed, so lets remove the details about it in store
		if err := l.client.DeleteRomanaIP(serviceName); err != nil {
			log.Errorf("error deleting romanaIP (%s) from romana kvstore",
				eip.RomanaIP.IP)
			continue
		}
	}
}

func (l *KubeListener) extractServiceDetails(svc interface{}) (
	*v1.Service, string, *api.ExposedIPSpec, error) {

	if svc == nil {
		// not a valid service, so ignore it
		return nil, "", nil, errors.New("error, received no service information")
	}

	service, ok := svc.(*v1.Service)
	if !ok {
		// not a valid service, so ignore it
		return nil, "", nil, errors.New("error, received no service information")
	}

	serviceName := service.GetName()
	if serviceName == "" {
		// no service name, so ignore it
		return nil, "", nil, errors.New("error, received no service name")
	}

	annotation := service.GetAnnotations()
	romanaAnnotation, ok := annotation["romanaip"]
	if !ok {
		// no romanaip annotation for service, so ignore it
		return nil, "", nil, fmt.Errorf("error, no romanaip annotation found for the service: %s",
			serviceName)
	}

	var romanaIP api.RomanaIP
	err := json.Unmarshal([]byte(romanaAnnotation), &romanaIP)
	if err != nil {
		// romanaip annotation is there, but not a
		// valid one thus return an error.
		return nil, "", nil, fmt.Errorf("error while accessing romanaIP annotation: %s", err)
	}

	// TODO: implement auto cidr mode for romanaIPs
	if romanaIP.Auto {
		return nil, "", nil, fmt.Errorf("romanaIP auto cidr mode not supported in this release")
	}

	if net.ParseIP(romanaIP.IP) == nil {
		return nil, "", nil, fmt.Errorf("romanaIP (%s) is not valid for service (%s)",
			romanaIP.IP, serviceName)
	}

	pods, err := l.kubeClientSet.CoreV1Client.Endpoints(service.GetNamespace()).List(
		v1.ListOptions{
			LabelSelector: labels.FormatLabels(service.GetLabels()),
		})
	if len(pods.Items) < 1 {
		return nil, "", nil, fmt.Errorf("pod not found for service (%s)", serviceName)
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("pod error for service (%s): %s",
			serviceName, err)
	}
	if !(len(pods.Items[0].Subsets) > 0 &&
		len(pods.Items[0].Subsets[0].Addresses) > 0) {
		return nil, "", nil, fmt.Errorf("node address not found for service (%s)",
			serviceName)
	}

	// use first pod to get node address for now until we support ipam
	// for romanaIP allocations.
	node, err := l.kubeClientSet.CoreV1Client.Nodes().Get(*pods.Items[0].Subsets[0].Addresses[0].NodeName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("node not found for pod for service (%s): %s",
			serviceName, err)
	}

	if len(node.Status.Addresses) < 1 {
		return nil, "", nil, fmt.Errorf("node address not found for node (%s)",
			node.Name)
	}

	namespace := service.GetNamespace()
	if namespace == "" {
		namespace = "default"
	}

	exposedIPSpec := api.ExposedIPSpec{
		RomanaIP:      romanaIP,
		NodeIPAddress: node.Status.Addresses[0].Address,
		Activated:     true,
		Namespace:     namespace,
	}

	return service, serviceName, &exposedIPSpec, nil
}

// kubernetesAddServiceEventHandler is called when Kubernetes reports an
// add service event It connects to the Romana agent and adds the service
// external IP as RomanaIP to the Romana cluster.
func (l *KubeListener) kubernetesAddServiceEventHandler(n interface{}) {
	service, ok := n.(*v1.Service)
	if !ok {
		log.Debugf("Error processing add event for service (%s) ", n)
		return
	}

	log.Infof("Add event received for service (%s) ", service.GetName())

	if err := l.updateRomanaIP(service); err != nil {
		log.Errorf("Error updating romanaIP for service (%s): %s",
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
		log.Debugf("Error processing update event for service (%s) ", n)
		return
	}

	log.Debugf("Update Event received for service (%s) ", service.GetName())

	if err := l.updateRomanaIP(service); err != nil {
		log.Errorf("Error updating romanaIP for service (%s): %s",
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
		log.Debugf("Error processing Delete Event received for service (%s) ", n)
		return
	}

	log.Infof("Delete event received for service (%s) ", service.GetName())

	l.deleteRomanaIP(service)
}

func (l *KubeListener) updateRomanaIP(service *v1.Service) error {
	RomanaExposedIPSpecMap.Lock()
	defer RomanaExposedIPSpecMap.Unlock()

	service, serviceName, exposedIPSpec, err := l.extractServiceDetails(service)
	if err != nil {
		log.Debugf("error fetching service details: %s", err)
		return nil
	}

	_, foundService := RomanaExposedIPSpecMap.IPForService[serviceName]
	if foundService {
		log.Debugf("Service (%s) already has romanaIP associated with it.",
			serviceName)
		return nil
	}

	updatedService := *service
	updatedService.Spec.ExternalIPs = []string{exposedIPSpec.RomanaIP.IP}
	namespace := updatedService.GetNamespace()
	if namespace == "" {
		namespace = "default"
	}
	_, err = l.kubeClientSet.CoreV1Client.Services(namespace).Update(&updatedService)
	if err != nil {
		return fmt.Errorf("externalIP couldn't be updated for service (%s): %s",
			serviceName, err)
	}

	if err := l.client.AddRomanaIP(serviceName, *exposedIPSpec); err != nil {
		return fmt.Errorf("error adding romanaIP (%s) to romana kvstore",
			exposedIPSpec.RomanaIP.IP)
	}

	RomanaExposedIPSpecMap.IPForService[serviceName] = *exposedIPSpec

	log.Tracef(trace.Private, "RomanaExposedIPSpecMap.IPForService: %v\n",
		RomanaExposedIPSpecMap.IPForService)

	return nil
}

func (l *KubeListener) deleteRomanaIP(service *v1.Service) {
	RomanaExposedIPSpecMap.Lock()
	defer RomanaExposedIPSpecMap.Unlock()

	serviceName := service.GetName()
	if serviceName == "" {
		return
	}

	exposedIPSpec, ok := RomanaExposedIPSpecMap.IPForService[serviceName]
	if !ok {
		log.Debugf("romanaIP for service (%s) not found in the list", serviceName)
		return
	}

	if err := l.client.DeleteRomanaIP(serviceName); err != nil {
		log.Errorf("error deleting romanaIP (%s) for service (%s) from romana kvstore",
			exposedIPSpec.RomanaIP.IP, serviceName)
		return
	}

	delete(RomanaExposedIPSpecMap.IPForService, serviceName)

	log.Tracef(trace.Private, "RomanaExposedIPSpecMap.IPForService: %v\n",
		RomanaExposedIPSpecMap.IPForService)
}
