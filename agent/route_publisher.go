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

package agent

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/romana/core/common"
	"github.com/romana/core/pkg/router/bird"
	router "github.com/romana/core/pkg/router/publisher"
	"github.com/romana/core/pkg/router/quagga"
	log "github.com/romana/rlog"
)

func PublishRoutesTo(provider string, config map[string]string, client *common.RestClient, networkConfig *NetworkConfig) chan net.IPNet {
	var publisher router.Interface
	var err error

	in := make(chan net.IPNet)

	if config == nil {
		if provider != "none" {
			log.Errorf("Route publisher is unable to start provider %s with nil config", provider)
		}

		return in
	}

	switch provider {
	case "none":
		return in
	case "bgp-quagga":
		publisher, err = quagga.New(router.Config(config))
		if err != nil {
			log.Errorf("Failed to start route publisher, err=(%s)", err)
		}
		romanaGw := net.IPNet{IP: networkConfig.RomanaGW(), Mask: networkConfig.RomanaGWMask()}
		go startPublishing(publisher, client, romanaGw, in)
	case "bird":
		publisher, err = bird.New(router.Config(config))
		if err != nil {
			log.Errorf("Failed to start route publisher, err=(%s)", err)
		}
		romanaGw := net.IPNet{IP: networkConfig.RomanaGW(), Mask: networkConfig.RomanaGWMask()}
		go startPublishing(publisher, client, romanaGw, in)
	}

	return in
}

const FullSyncPeriod time.Duration = time.Duration(3 * time.Minute)
const CacheSyncPeriod time.Duration = time.Duration(1 * time.Second)

func startPublishing(publisher router.Interface, client *common.RestClient, romanaGw net.IPNet, in <-chan net.IPNet) {
	Cache := NewIpamCache()
	fullTick := time.Tick(FullSyncPeriod)
	cacheTick := time.Tick(CacheSyncPeriod)

	for {
		select {
		case net, ok := <-in:
			log.Debugf("Route publisher: net network %s", net)
			if !ok {
				log.Debug("Route publisher: input channel closed")
				continue
			}
			Cache.Add(net)
		case <-fullTick:
			log.Debugf("Route publisher: full tick")
			networks, err := getSlash32Networks(client)
			if err != nil {
				log.Errorf("Route publisher: %s", err)
			}
			Cache.Replace(filterNetworksByRomanaGw(romanaGw, networks))
		case <-cacheTick:
			log.Debugf("Route publisher: cache tick")
			if networks, ok := Cache.ListIfClean(); ok {
				err1 := publisher.Update(networks)
				if err1 != nil {
					log.Errorf("Failed to publish routes, err=(%s)", err1)
				}
			}
		}
	}
}

// ListIpamEndpoints returns list of ipam endpoints.
func ListIpamEndpoints(client *common.RestClient) ([]common.IPAMEndpoint, error) {
	var endpoints []common.IPAMEndpoint

	ipamUrl, err := client.GetServiceUrl("ipam")
	if err != nil {
		return endpoints, fmt.Errorf("Route publisher failed to connect to IPAM, err=(%s)", err)
	}

	ipamUrl += "/endpoints"

	err = client.Get(ipamUrl, &endpoints)
	if err != nil {
		return endpoints, fmt.Errorf("Route publisher failed to connect to IPAM, err=(%s)", err)
	}

	return endpoints, nil
}

func getSlash32Networks(client *common.RestClient) ([]net.IPNet, error) {
	endpoints, err := ListIpamEndpoints(client)
	if err != nil {
		return nil, err
	}

	var networks []net.IPNet
	for _, endpoint := range endpoints {
		if !endpoint.InUse {
			continue
		}

		_, network, err := net.ParseCIDR(fmt.Sprintf("%s/32", endpoint.Ip))
		if err != nil {
			log.Errorf("Route publisher skipping %s, err=(%s)", endpoint.Ip, err)
		}

		networks = append(networks, *network)
	}

	return networks, nil
}

func filterNetworksByRomanaGw(romanaGw net.IPNet, allNetworks []net.IPNet) []net.IPNet {
	var networks []net.IPNet
	for _, network := range allNetworks {
		if romanaGw.Contains(network.IP) {
			networks = append(networks, network)
		}
	}

	return networks
}

// ParseRoutePublisherConfig attempts to parse configuration value of
// `route_publisher_config` variable. Config will pass the variable as intrface{}
// and we need to ensure it's a valid map[string]string.
func ParseRoutePublisherConfig(incoming interface{}) (map[string]string, error) {
	configMap := make(map[string]string)

	switch incomingMap := incoming.(type) {
	case map[string]interface{}:
		for k, v := range incomingMap {
			if valStr, ok := v.(string); ok {
				configMap[k] = valStr
			} else {
				log.Errorf("Skipping route publisher configuration key, can't convert to string %s = %v.(%T)", k, v, v)
			}
		}
	default:
		return configMap, fmt.Errorf("Failed to parse route publisher config, %v.(%T)", incomingMap, incomingMap)
	}

	return configMap, nil
}

func NewIpamCache() IpamCache {
	data := make(map[string]net.IPNet)
	return IpamCache{data: data}
}

type IpamCache struct {
	sync.Mutex
	dirty bool
	// use map just to ensure uniquness
	data map[string]net.IPNet
}

func (i *IpamCache) Add(network net.IPNet) {
	i.Lock()
	defer i.Unlock()
	i.data[network.String()] = network
	i.dirty = true
}

func (i *IpamCache) Remove(network net.IPNet) {
	i.Lock()
	defer i.Unlock()
	delete(i.data, network.String())
	i.dirty = true
}

func (i *IpamCache) Replace(networks []net.IPNet) {
	i.Lock()
	defer i.Unlock()
	data := make(map[string]net.IPNet)

	for _, net := range networks {
		data[net.String()] = net
	}
	i.data = data
	i.dirty = true
}

// ListIfClean returns contents of a the cache only if it's dirty
// otherwise returns empty list.
func (i *IpamCache) ListIfClean() ([]net.IPNet, bool) {
	i.Lock()
	defer i.Unlock()

	var list []net.IPNet
	if !i.dirty {
		return list, false
	}

	for _, net := range i.data {
		list = append(list, net)
	}
	i.dirty = false
	return list, true
}
