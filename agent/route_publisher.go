// Copyright (c) 2016 Pani Networks
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
	"github.com/romana/core/common"
	router "github.com/romana/core/pkg/routepublisher/quaggabgp"
	log "github.com/romana/rlog"
	"net"
	"time"
)

func PublishRoutesTo(provider string, config map[string]string, client *common.RestClient) {
	var publisher router.Interface
	var err error

	if config == nil {
		if provider != "none" {
			log.Errorf("Route publisher is unable to start provider %s with nil config", provider)
		}

		return
	}

	switch provider {
	case "none":
		return
	case "bgp-quagga":
		publisher, err = router.New(router.Config(config))
		if err != nil {
			log.Errorf("Failed to start route publisher, err=(%s)", err)
		}
		go startPublishing(publisher, client)
	}

	return
}

const routerPublisherSleepDuration = 30

func startPublishing(publisher router.Interface, client *common.RestClient) {
	for {
		// TODO stas, timer duration not configurable because it's terrible idea
		// anyway. Client would expect subsecond convergance wich can't be achieved
		// through polling DB and harrasing routing daemon every second.
		// There has to be some queue.
		time.Sleep(time.Duration(routerPublisherSleepDuration * time.Second))

		ipamUrl, err := client.GetServiceUrl("ipam")
		if err != nil {
			log.Errorf("Route publisher failed to connect to IPAM, err=(%s)", err)
			continue
		}

		ipamUrl += "/endpoints"
		var endpoints []common.IPAMEndpoint

		err = client.Get(ipamUrl, &endpoints)
		if err != nil {
			log.Errorf("Route publisher failed to connect to IPAM, err=(%s)", err)
			continue
		}

		var networks []net.IPNet
		for _, endpoint := range endpoints {
			_, network, err := net.ParseCIDR(fmt.Sprintf("%s/32", endpoint.Ip))
			if err != nil {
				log.Errorf("Route publisher skipping %s, err=(%s)", endpoint.Ip, err)
			}

			networks = append(networks, *network)
		}

		publisher.Update(networks)
	}
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
