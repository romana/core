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

package main

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/romana/core/agent"
	"github.com/romana/core/common"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
)

const DefaultSegmentName = "default"

// AgentUrl is a constant since CNI plugin should always live on the same node
// as the agent and port should probably stay the same. This might require attention
// in future.
const AgentUrl = "http://localhost:9604/pod"

// RomanaAddressManager describes functions that allow allocating and deallocating
// IP addresses from Romana.
type RomanaAddressManager interface {
	Allocate(NetConf, *common.RestClient, RomanaAllocatorPodDescription) (*net.IPNet, error)
	Deallocate(NetConf, *common.RestClient, string) error
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
	RomanaRoot       string `json:"romana_root"`

	// Name of a current host in romana.
	// If omitted, current hostname will be used.
	RomanaHostName   string `json:"romana_host_name"`
	SegmentLabelName string `json:"segment_label_name"`
	TenantLabelName  string `json:"tenant_label_name"` // TODO for stas, we don't use it. May be it should go away.
	UseAnnotations   bool   `json:"use_annotattions"`
}

type DefaultAddressManager struct{}

func (DefaultAddressManager) Allocate(config NetConf, client *common.RestClient, pod RomanaAllocatorPodDescription) (*net.IPNet, error) {
	// Discover pod segment.
	var segmentLabel string
	var ok bool
	if config.UseAnnotations {
		segmentLabel, ok = pod.Annotations[config.SegmentLabelName]
	} else {
		segmentLabel, ok = pod.Labels[config.SegmentLabelName]
	}
	if !ok {
		log.Warnf("Failed to discover segment label for a pod, using %s", DefaultSegmentName)
		segmentLabel = DefaultSegmentName
	}
	log.Infof("Discovered segment %s for a pod", segmentLabel)

	// Topology, find host id.
	hosts, err := client.ListHosts()
	if err != nil {
		return nil, fmt.Errorf("Failed to list romana hosts err=(%s)", err)
	}
	var currentHost common.Host
	for hostNum, host := range hosts {
		if host.Name == config.RomanaHostName {
			currentHost = hosts[hostNum]
			break
		}
	}
	if currentHost.Name == "" {
		return nil, fmt.Errorf("Failed to find romana host with name %s in romana database", config.RomanaHostName)
	}

	// Tenant and segemnt
	tenantUrl, err := client.GetServiceUrl("tenant")
	if err != nil {
		return nil, fmt.Errorf("Failed to discover tenant url from romana root err=(%s)", err)
	}
	tenantUrl += "/tenants"
	var tenants []common.Tenant
	err = client.Get(tenantUrl, &tenants)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch romana tenants from %s, err=(%s)", tenantUrl, err)
	}
	var currentTenant common.Tenant
	for tenantNum, tenant := range tenants {
		if tenant.Name == pod.Namespace {
			currentTenant = tenants[tenantNum]
			break
		}
	}
	if currentTenant.Name == "" {
		return nil, fmt.Errorf("Failed to find romana tenant with name %s, err=(%s)", pod.Namespace, err)
	}

	currentSegment, err := getOrCreateSegment(client, segmentLabel, tenantUrl, currentTenant.ID)
	if err != nil {
		return nil, fmt.Errorf("Failed to discover segment %s within tenant %s", pod.Namespace, segmentLabel)
	}
	log.Infof("Discovered tenant=%d, segment=%d, host=%d", currentTenant.ID, currentSegment.ID, currentHost.ID)

	// IPAM allocate
	ipamUrl, err := client.GetServiceUrl("ipam")
	if err != nil {
		return nil, fmt.Errorf("Failed to discover ipam url from romana root err=(%s)", err)
	}
	ipamUrl += "/endpoints"
	var ipamReq, ipamResp common.IPAMEndpoint
	ipamReq = common.IPAMEndpoint{
		TenantID:  fmt.Sprintf("%d", currentTenant.ID),
		SegmentID: fmt.Sprintf("%d", currentSegment.ID),
		HostId:    fmt.Sprintf("%d", currentHost.ID),
		Name:      pod.Name,
	}
	err = client.Post(ipamUrl, &ipamReq, &ipamResp)
	if err != nil {
		return nil, fmt.Errorf("Failed to allocate IP address for a pod %s.%s, err=(%s)", pod.Namespace, currentTenant.Name, err)
	}
	log.Infof("Allocated IP address %s", ipamResp.Ip)
	ipamIP, err := netlink.ParseIPNet(ipamResp.Ip + "/32")
	if err != nil {
		return nil, fmt.Errorf("Failed to parse IP address %s, err=(%s)", ipamResp.Ip, err)
	}

	return ipamIP, nil
}

func (DefaultAddressManager) Deallocate(config NetConf, client *common.RestClient, targetName string) error {
	ipamUrl, err := client.GetServiceUrl("ipam")
	if err != nil {
		return fmt.Errorf("Failed to discover ipam url from romana root err=(%s)", err)
	}
	ipamUrl += "/endpoints"

	var endpoints, podEndpoints []common.IPAMEndpoint
	err = client.Get(ipamUrl, &endpoints)
	if err != nil {
		return fmt.Errorf("Failed to fetch ipam endpoints, err=(%s)", err)
	}

	for eNum, endpoint := range endpoints {
		if endpoint.Name == targetName && endpoint.InUse {
			podEndpoints = append(podEndpoints, endpoints[eNum])
		}
	}

	// Not reporting an error here because kubelet will keep trying
	// to deallocate this endpoint until we return success.
	if len(podEndpoints) == 0 {
		log.Errorf("cni tried to deallocate %s but couldn't find such endpoint", targetName)
		return nil
	}

	if len(podEndpoints) > 1 {
		return fmt.Errorf("Multiple IPAM endpoints found for pod %s, not supported", targetName)
	}

	endpointDeleteUrl := fmt.Sprintf("%s/%s", ipamUrl, podEndpoints[0].Ip)
	err = client.Delete(endpointDeleteUrl, nil, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete IPAM endpoint %v", podEndpoints[0])
	}

	return nil
}

func getOrCreateSegment(client *common.RestClient, segmentLabel, tenantUrl string, tenantId uint64) (*common.Segment, error) {
	var segments []common.Segment
	segmentsUrl := fmt.Sprintf("%s/%d/segments", tenantUrl, tenantId)
	err := client.Get(segmentsUrl, &segments)
	// ignore 404 error here which means no segments
	// considered to be a zero segments rather then
	// an error.
	if err != nil && !checkHttp404(err) {
		return nil, fmt.Errorf("Failed to fetch segments from %s, err=(%s)", segmentsUrl, err)
	}

	for segmentNum, segment := range segments {
		if segment.Name == segmentLabel {
			return &segments[segmentNum], nil
		}
	}

	log.Errorf("no segment %s found, trying to create", segmentLabel)

	var newSegment common.Segment
	err = client.Post(segmentsUrl, common.Segment{Name: segmentLabel}, &newSegment)
	if err != nil {
		return nil, fmt.Errorf("failed to create segment %s, err=(%s)", segmentsUrl, err)
	}

	log.Infof("new segment created %v for tenant with id %d", newSegment, tenantId)

	return &newSegment, nil
}

func checkHttp404(err error) (ret bool) {
	switch e := err.(type) {
	case common.HttpError:
		if e.StatusCode == 404 {
			ret = true
		}
	}

	return
}

// MakeRomanaClient creates romana rest client from CNI config.
func MakeRomanaClient(config *NetConf) (*common.RestClient, error) {
	clientConfig := common.GetDefaultRestClientConfig(config.RomanaRoot, nil)
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to reach romana root at %s, err=(%s)", config.RomanaRoot, err)
	}
	log.Infof("Created romana client %v", client)

	return client, nil
}

const (
	// Parameter for NotifyAgent, notifies Romana agent that pod is added.
	NotifyPodUp = "pod added"

	// Parameter for NotifyAgent, notifies Romana agent that pod is deleted.
	NotifyPodDown = "pod deleted"
)

// NotifyAgent notifies Romana agent that Pod is added or deleted.
func NotifyAgent(client *common.RestClient, ip *net.IPNet, iface string, op string) (err error) {
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
		err = client.Post(AgentUrl, agent.NetworkRequest{NetIf: netif}, nil)
	case NotifyPodDown:
		err = client.Delete(AgentUrl, agent.NetworkRequest{NetIf: netif}, nil)
	default:
	}

	return err
}
