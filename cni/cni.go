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

package cni

import (
	"fmt"
	"net"
	"net/http"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/go-resty/resty"
	"github.com/romana/core/agent"
	"github.com/romana/core/common"
	"github.com/romana/core/common/client"
	"github.com/romana/core/listener"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
)

const DefaultSegmentID = "default"

// AgentUrl is a constant since CNI plugin should always live on the same node
// as the agent and port should probably stay the same. This might require attention
// in future.
const AgentUrl = "http://localhost:9604/pod"

// RomanaAddressManager describes functions that allow allocating and deallocating
// IP addresses from Romana.
type RomanaAddressManager interface {
	Allocate(NetConf, *client.Client, RomanaAllocatorPodDescription) (*net.IPNet, error)
	Deallocate(NetConf, *client.Client, string) error
}

// NewRomanaAddressManager returns structure that satisfies RomanaAddresManager,
// it allows multiple implementations.
func NewRomanaAddressManager(provider RomanaAddressManagerProvider) (RomanaAddressManager, error) {
	if provider == DefaultProvider {
		return DefaultAddressManager{}, nil
	}

	return nil, fmt.Errorf("Unknown provider type %s", provider)
}

type RomanaAddressManagerProvider string

// DefaultProvider allocates and deallocates IP addresses using rest requests
// to Romana IPAM.
const DefaultProvider RomanaAddressManagerProvider = "default"

// RomanaAllocatorPodDescription represents collection of parameters used to allocate IP address.
type RomanaAllocatorPodDescription struct {
	Name        string
	Hostname    string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
}

// NetConf represents parameters CNI plugin receives via stdin.
type NetConf struct {
	types.NetConf
	KubernetesConfig string `json:"kubernetes_config"`

	RomanaClientConfig common.Config `json:"romana_client_config"`

	// Name of a current host in romana.
	// If omitted, current hostname will be used.
	RomanaHostName   string `json:"romana_host_name"`
	SegmentLabelName string `json:"segment_label_name"`
	TenantLabelName  string `json:"tenant_label_name"` // TODO for stas, we don't use it. May be it should go away.
	UseAnnotations   bool   `json:"use_annotations"`
}

type DefaultAddressManager struct{}

func (DefaultAddressManager) Allocate(config NetConf, client *client.Client, pod RomanaAllocatorPodDescription) (*net.IPNet, error) {
	// Discover pod segment.
	var segmentID string
	var ok bool
	if config.UseAnnotations {
		segmentID, ok = pod.Annotations[config.SegmentLabelName]
	} else {
		segmentID, ok = pod.Labels[config.SegmentLabelName]
	}
	if !ok {
		log.Warnf("Failed to discover segment label for a pod, using %s", DefaultSegmentID)
		segmentID = DefaultSegmentID
	}
	tenantID := listener.GetTenantIDFromNamespaceName(pod.Namespace)

	ip, err := client.IPAM.AllocateIP(pod.Name, config.RomanaHostName, tenantID, segmentID)
	log.Infof("Allocated IP address %s", ip)

	if err != nil {
		return nil, fmt.Errorf("Failed to allocate IP: %s", err)
	}
	if ip == nil {
		return nil, fmt.Errorf("No more IPs available.")
	}

	ipamIP, err := netlink.ParseIPNet(ip.String() + "/32")
	if err != nil {
		return nil, fmt.Errorf("Failed to parse IP address %s, err=(%s)", ip, err)
	}

	return ipamIP, nil
}

func (DefaultAddressManager) Deallocate(config NetConf, client *client.Client, targetName string) error {
	err := client.IPAM.DeallocateIP(targetName)
	if httpE, ok := err.(common.HttpError); ok && httpE.StatusCode == http.StatusNotFound {
		log.Errorf("CNI attempted to deallocate %s but got %s, suppressing error to prevent kubelet from retries", targetName, httpE)
		return nil
	}

	return err
}

// MakeRomanaClient creates romana rest client from CNI config.
func MakeRomanaClient(config *NetConf) (*client.Client, error) {
	var err error
	client, err := client.NewClient(&config.RomanaClientConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

const (
	// Parameter for NotifyAgent, notifies Romana agent that pod is added.
	NotifyPodUp = "pod added"

	// Parameter for NotifyAgent, notifies Romana agent that pod is deleted.
	NotifyPodDown = "pod deleted"
)

// NotifyAgent notifies Romana agent that Pod is added or deleted.
func NotifyAgent(ip *net.IPNet, iface string, op string) (err error) {
	var address agent.IP
	if ip != nil {
		address = agent.IP{IP: ip.IP}
	} else {
		address = agent.IP{IP: net.ParseIP("127.0.0.1")}
	}
	log.Infof("Notify romana agent about %s with ip %v, on interface %s", op, address, iface)

	netif := agent.NetIf{Name: iface, IP: address}
	switch op {
	case NotifyPodUp:
		_, err := resty.R().SetBody(agent.NetworkRequest{NetIf: netif}).Post(AgentUrl)
		return err
	case NotifyPodDown:
		_, err := resty.R().SetBody(agent.NetworkRequest{NetIf: netif}).Delete(AgentUrl)
		return err
	default:
	}

	return nil
}
