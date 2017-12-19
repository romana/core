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
	serviceSyncTimer = 60 * time.Second
)

func (l *KubeListener) startRomanaVIPSync(stop <-chan struct{}) {
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
				go l.startRomanaVIPPeriodicSync(stop, serviceStore)
				return
			}
		case <-stop:
			log.Info("received stop request from listener")
			return
		}
	}
}

func (l *KubeListener) startRomanaVIPPeriodicSync(stop <-chan struct{}, serviceStore cache.Store) {
	serviceSyncTicker := time.NewTicker(serviceSyncTimer)
	defer serviceSyncTicker.Stop()
	var romanaVIPPeriodicSyncMutex sync.Mutex

	// run syncRomanaVIPs and syncExposedIPs once before running
	// them at the interval of serviceSyncTimer, since ticker
	// skips the 0th interval and starts from the first
	// serviceSyncTimer interval.
	romanaVIPPeriodicSyncMutex.Lock()
	l.syncRomanaVIPs(serviceStore)
	l.syncExposedIPs()
	romanaVIPPeriodicSyncMutex.Unlock()

	for {
		select {
		case <-serviceSyncTicker.C:
			romanaVIPPeriodicSyncMutex.Lock()
			l.syncRomanaVIPs(serviceStore)
			l.syncExposedIPs()
			romanaVIPPeriodicSyncMutex.Unlock()
		case <-stop:
			log.Info("received stop request from listener")
			return
		}
	}
}

func (l *KubeListener) syncRomanaVIPs(serviceStore cache.Store) {
	serviceListAll := serviceStore.List()
	romanaVIPMap := make(map[string]api.ExposedIPSpec)
	serviceMap := make(map[string]v1.Service)

	for i := range serviceListAll {
		service, key, exposedIPSpec, err := l.extractServiceDetails(serviceListAll[i])
		if err != nil {
			log.Debugf("error fetching service details: %s", err)
			continue
		}

		romanaVIPMap[key] = *exposedIPSpec
		serviceMap[key] = *service
	}

	// if no service with romana VIP annotation is found, skip
	// syncing, since there is nothing to be done here.
	if len(romanaVIPMap) == 0 && len(l.romanaExposedIPSpecMap.IPForService) == 0 {
		return
	}

	l.romanaExposedIPSpecMap.Lock()

	// update/add new services which we see
	for key, rip := range romanaVIPMap {
		eip, ok := l.romanaExposedIPSpecMap.IPForService[key]

		if ok && eip.RomanaVIP.IP == rip.RomanaVIP.IP &&
			eip.NodeIPAddress == rip.NodeIPAddress {
			// romana VIP is present, and match the current romana
			// VIP configuration, so nothing to be done here.
			continue
		}

		// update service locally for external IP
		updatedService := serviceMap[key]
		updatedService.Spec.ExternalIPs = []string{rip.RomanaVIP.IP}
		_, err := l.kubeClientSet.CoreV1Client.Services(rip.Namespace).Update(&updatedService)
		if err != nil {
			log.Errorf("externalIP couldn't be updated for service (%s): %s",
				key, err)
			continue
		}

		// everything seems fine and addition/updating romana VIP was
		// a success and thus add the romana VIP to the exposedIP map here.
		l.romanaExposedIPSpecMap.IPForService[key] = rip
	}

	// remove old services not seen anymore in service list.
	for key := range l.romanaExposedIPSpecMap.IPForService {
		_, ok := romanaVIPMap[key]
		if ok {
			// service is present, so nothing to be done here.
			continue
		}

		// service was removed, so lets remove the details about it here
		delete(l.romanaExposedIPSpecMap.IPForService, key)
	}

	l.romanaExposedIPSpecMap.Unlock()
}

func (l *KubeListener) syncExposedIPs() {
	l.romanaExposedIPSpecMap.Lock()
	defer l.romanaExposedIPSpecMap.Unlock()

	exposedIPMap, err := l.client.ListRomanaVIPs()
	if err != nil {
		return
	}

	for key, rip := range l.romanaExposedIPSpecMap.IPForService {
		eip, ok := exposedIPMap[key]

		if ok && eip.RomanaVIP.IP == rip.RomanaVIP.IP &&
			eip.NodeIPAddress == rip.NodeIPAddress {
			// romana VIP is present, and match the current romana
			// VIP configuration, so nothing to be done here.
			continue
		}

		// if this is romana VIP update, then lets remove it first
		if ok && (eip.RomanaVIP.IP != rip.RomanaVIP.IP ||
			eip.NodeIPAddress != rip.NodeIPAddress) {
			if err := l.client.DeleteRomanaVIP(key); err != nil {
				// log the error and then do nothing here since
				// even if deleting fails, it could be that the
				// service didn't exists,  the addition happens
				// below. so it should be ok to continue below
				// here.
				log.Debugf("error updating romana VIP (%s:%s) for service (%s) on node (%s:%s)",
					eip.RomanaVIP.IP, rip.RomanaVIP.IP, key,
					eip.NodeIPAddress, rip.NodeIPAddress)
			}
		}

		// add to kvstore so that agent adds
		// appropriate external IP on node
		if err := l.client.AddRomanaVIP(key, rip); err != nil {
			log.Errorf("error adding romana VIP (%s) to romana kvstore",
				rip.RomanaVIP.IP)
			continue
		}
	}

	// remove old services not seen anymore in service list.
	for key, eip := range exposedIPMap {
		_, ok := l.romanaExposedIPSpecMap.IPForService[key]
		if ok {
			// service is present, so nothing to be done here.
			continue
		}

		// service was removed, so lets remove the details about it in store
		if err := l.client.DeleteRomanaVIP(key); err != nil {
			log.Errorf("error deleting romana VIP (%s) from romana kvstore",
				eip.RomanaVIP.IP)
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
		return nil, "", nil, errors.New("error, received service information is not compatible")
	}

	serviceName := service.GetName()
	if serviceName == "" {
		// no service name, so ignore it
		return nil, "", nil, errors.New("error, received no service name")
	}

	annotation := service.GetAnnotations()
	romanaAnnotation, ok := annotation["romanavip"]
	if !ok {
		// no romana VIP annotation for service, so ignore it
		return nil, "", nil, fmt.Errorf("error, no romana VIP annotation found for the service: %s",
			serviceName)
	}

	var romanaVIP api.RomanaVIP
	err := json.Unmarshal([]byte(romanaAnnotation), &romanaVIP)
	if err != nil {
		// romana VIP annotation is there, but not a
		// valid one thus return an error.
		return nil, "", nil, fmt.Errorf("error while accessing romana VIP annotation: %s", err)
	}

	// TODO: implement auto cidr mode for romana VIPs
	if romanaVIP.Auto {
		return nil, "", nil, fmt.Errorf("romana VIP auto cidr mode not supported in this release")
	}

	if net.ParseIP(romanaVIP.IP) == nil {
		return nil, "", nil, fmt.Errorf("romana VIP (%s) is not valid for service (%s)",
			romanaVIP.IP, serviceName)
	}

	namespace := service.GetNamespace()
	if namespace == "" {
		namespace = "default"
	}

	key := serviceName + "." + namespace

	pods, err := l.kubeClientSet.CoreV1Client.Endpoints(namespace).List(
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
	// for romana VIP allocations.
	node, err := l.kubeClientSet.CoreV1Client.Nodes().Get(*pods.Items[0].Subsets[0].Addresses[0].NodeName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("node not found for pod for service (%s): %s",
			serviceName, err)
	}

	if len(node.Status.Addresses) < 1 {
		return nil, "", nil, fmt.Errorf("node address not found for node (%s)",
			node.Name)
	}

	exposedIPSpec := api.ExposedIPSpec{
		RomanaVIP:     romanaVIP,
		NodeIPAddress: node.Status.Addresses[0].Address,
		Activated:     true,
		Namespace:     namespace,
	}

	return service, key, &exposedIPSpec, nil
}

// kubernetesAddServiceEventHandler is called when Kubernetes reports an
// add service event It connects to the Romana agent and adds the service
// external IP as RomanaVIP to the Romana cluster.
func (l *KubeListener) kubernetesAddServiceEventHandler(n interface{}) {
	service, ok := n.(*v1.Service)
	if !ok {
		log.Debugf("Error processing add event for service (%s) ", n)
		return
	}

	log.Infof("Add event received for service (%s) ", service.GetName())

	if err := l.updateRomanaVIP(service); err != nil {
		log.Errorf("Error updating romana VIP for service (%s): %s",
			service.Name, err)
		return
	}
}

// kubernetesUpdateServiceEventHandler is called when Kubernetes reports an
// update service event. It connects to the Romana agent and updates the service
// external IP as RomanaVIP to the Romana cluster.
func (l *KubeListener) kubernetesUpdateServiceEventHandler(o, n interface{}) {
	service, ok := n.(*v1.Service)
	if !ok {
		log.Debugf("Error processing update event for service (%s) ", n)
		return
	}

	log.Debugf("Update Event received for service (%s) ", service.GetName())

	if err := l.updateRomanaVIP(service); err != nil {
		log.Errorf("Error updating romana VIP for service (%s): %s",
			service.Name, err)
		return
	}
}

// kubernetesDeleteServiceEventHandler is called when Kubernetes reports a
// delete service event. It connects to the Romana agent and deletes the
// RomanaVIP from the Romana cluster.
func (l *KubeListener) kubernetesDeleteServiceEventHandler(n interface{}) {
	service, ok := n.(*v1.Service)
	if !ok {
		log.Debugf("Error processing Delete Event received for service (%s) ", n)
		return
	}

	log.Infof("Delete event received for service (%s) ", service.GetName())

	l.deleteRomanaVIP(service)
}

func (l *KubeListener) updateRomanaVIP(service *v1.Service) error {
	l.romanaExposedIPSpecMap.Lock()
	defer l.romanaExposedIPSpecMap.Unlock()

	service, key, exposedIPSpec, err := l.extractServiceDetails(service)
	if err != nil {
		log.Debugf("error fetching service details: %s", err)
		return nil
	}

	_, foundService := l.romanaExposedIPSpecMap.IPForService[key]
	if foundService {
		log.Debugf("Service (%s) already has romana VIP associated with it.",
			key)
		return nil
	}

	updatedService := *service
	updatedService.Spec.ExternalIPs = []string{exposedIPSpec.RomanaVIP.IP}
	_, err = l.kubeClientSet.CoreV1Client.Services(exposedIPSpec.Namespace).Update(&updatedService)
	if err != nil {
		return fmt.Errorf("externalIP couldn't be updated for service (%s): %s",
			service.GetName(), err)
	}

	if err := l.client.AddRomanaVIP(key, *exposedIPSpec); err != nil {
		return fmt.Errorf("error adding romana VIP (%s) to romana kvstore",
			exposedIPSpec.RomanaVIP.IP)
	}

	l.romanaExposedIPSpecMap.IPForService[key] = *exposedIPSpec

	log.Tracef(trace.Private, "RomanaExposedIPSpecMap.IPForService: %v\n",
		l.romanaExposedIPSpecMap.IPForService)

	return nil
}

func (l *KubeListener) deleteRomanaVIP(service *v1.Service) {
	l.romanaExposedIPSpecMap.Lock()
	defer l.romanaExposedIPSpecMap.Unlock()

	serviceName := service.GetName()
	if serviceName == "" {
		return
	}
	namespace := service.GetNamespace()
	if namespace == "" {
		namespace = "default"
	}
	key := serviceName + "." + namespace

	exposedIPSpec, ok := l.romanaExposedIPSpecMap.IPForService[key]
	if !ok {
		log.Debugf("romana VIP for service (%s) not found in the list", serviceName)
		return
	}

	if err := l.client.DeleteRomanaVIP(key); err != nil {
		log.Errorf("error deleting romana VIP (%s) for service (%s) from romana kvstore",
			exposedIPSpec.RomanaVIP.IP, serviceName)
		return
	}

	delete(l.romanaExposedIPSpecMap.IPForService, key)

	log.Tracef(trace.Private, "RomanaExposedIPSpecMap.IPForService: %v\n",
		l.romanaExposedIPSpecMap.IPForService)
}
