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
	"encoding/json"
	"fmt"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/1.5/kubernetes"
	"net"
	"os"
	"runtime"

	"github.com/romana/core/common"
	"k8s.io/client-go/1.5/tools/clientcmd"
	//	"github.com/romana/core/common/log/trace"
)

var hostname string

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()

	// TODO for stas, can we avoid this?
	hostname, _ = os.Hostname()
}

// The structure should be in separate file.
type FeatureIP6TW struct {
	// Fields relative to the feature.
}

type NetConf struct {
	FeatureIP6TW
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

// K8sArgs is the valid CNI_ARGS used for Kubernetes
type K8sArgs struct {
	types.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}

func (k8s K8sArgs) makePodName() string {
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

func (k8s K8sArgs) makeVethName() string {
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

func loadConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %s", err)
	}

	// TODO for stas
	// verify config here
	if n.RomanaHostName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, "", fmt.Errorf("failed to load netconf: %s", err)
		}

		n.RomanaHostName = hostname
	}

	return n, n.CNIVersion, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	var err error
	// Stdin args have romana related config.
	// Loaded via loadConf into NetConf.
	netConf, _, _ := loadConf(args.StdinData)
	cniVersion := netConf.CNIVersion

	// environment variables have CNI related config (CNI_COMMAND, CNI_IFNAME, CNI_NETNS, CNI_CONTAINERID, CNI_PATH, CNI_ARGS).
	// Loaded via skel.getCmdAgrsFromEnv into skel.CmdArgs

	// CNI_ARGS contain additional K8S config (IP, K8S_POD_NAME, K8S_POD_NAMESPACE, K8S_POD_INFRA_CONTAINER_ID, IgnoreUnknown)
	// Laded via cni.types.LoadArgs into  K8sArgs
	k8sargs := K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sargs)
	if err != nil {
		return err
	}

	// Init kubernetes client. Attempt to load from statically configured k8s config or fallback on in-cluster
	kubeClientConfig, err := clientcmd.BuildConfigFromFlags("", netConf.KubernetesConfig)
	if err != nil {
		return err
	}
	kubeClient, err := kubernetes.NewForConfig(kubeClientConfig)

	pod, err := kubeClient.Core().Pods(string(k8sargs.K8S_POD_NAMESPACE)).Get(fmt.Sprintf("%s", k8sargs.K8S_POD_NAME))
	if err != nil {
		return err
	}

	// Discover pod segment.
	var segmentLabel string
	var ok bool
	if netConf.UseAnnotations {
		segmentLabel, ok = pod.Annotations[netConf.SegmentLabelName]
	} else {
		segmentLabel, ok = pod.Labels[netConf.SegmentLabelName]
	}
	if !ok {
		return fmt.Errorf("Failed to discover segment label for a pod")
	}
	log.Infof("Discovered segment %s for a pod", segmentLabel)

	// Rest client config
	clientConfig := common.GetDefaultRestClientConfig(netConf.RomanaRoot, nil)
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		return fmt.Errorf("Failed to reach romana root at %s, err=(%s)", netConf.RomanaRoot, err)
	}
	log.Infof("Created romana client %v", client)

	// Topology, find host id.
	hosts, err := client.ListHosts()
	if err != nil {
		fmt.Errorf("Failed to list romana hosts err=(%s)", err)
	}
	var currentHost common.Host
	for hostNum, host := range hosts {
		if host.Name == netConf.RomanaHostName {
			currentHost = hosts[hostNum]
			break
		}
	}
	if currentHost.Name == "" {
		return fmt.Errorf("Failed to find romana host with name %s in romana database", netConf.RomanaHostName)
	}

	// Tenant and segemnt
	tenantUrl, err := client.GetServiceUrl("tenant")
	if err != nil {
		return fmt.Errorf("Failed to discover tenant url from romana root err=(%s)", err)
	}
	tenantUrl += "/tenants"
	var tenants []common.Tenant
	err = client.Get(tenantUrl, &tenants)
	if err != nil {
		return fmt.Errorf("Failed to fetch romana tenants from %s, err=(%s)", tenantUrl, err)
	}
	var currentTenant common.Tenant
	for tenantNum, tenant := range tenants {
		if tenant.Name == string(k8sargs.K8S_POD_NAMESPACE) {
			currentTenant = tenants[tenantNum]
			break
		}
	}
	if currentTenant.Name == "" {
		return fmt.Errorf("Failed to find romana tenant with name %s, err=(%s)", k8sargs.K8S_POD_NAMESPACE, err)
	}
	var segments []common.Segment
	segmentsUrl := fmt.Sprintf("%s/%d/segments", tenantUrl, currentTenant.ID)
	err = client.Get(segmentsUrl, &segments)
	if err != nil {
		return fmt.Errorf("Failed to fetch segments from %s, err=(%s)", segmentsUrl, err)
	}
	var currentSegment common.Segment
	for segmentNum, segment := range segments {
		if segment.Name == segmentLabel {
			currentSegment = segments[segmentNum]
			break
		}
	}
	if currentSegment.Name == "" {
		return fmt.Errorf("Failed to discover segment %s within tenant %s", k8sargs.K8S_POD_NAMESPACE, segmentLabel)
	}
	log.Infof("Discovered tenant=%d, segment=%d, host=%d", currentTenant.ID, currentSegment.ID, currentHost.ID)

	// IPAM allocate
	ipamUrl, err := client.GetServiceUrl("ipam")
	if err != nil {
		return fmt.Errorf("Failed to discover ipam url from romana root err=(%s)", err)
	}
	ipamUrl += "/endpoints"
	var ipamReq, ipamResp common.IPAMEndpoint
	ipamReq = common.IPAMEndpoint{
		TenantID:  fmt.Sprintf("%d", currentTenant.ID),
		SegmentID: fmt.Sprintf("%d", currentSegment.ID),
		HostId:    fmt.Sprintf("%d", currentHost.ID),
		Name:      k8sargs.makePodName(),
	}
	err = client.Post(ipamUrl, &ipamReq, &ipamResp)
	if err != nil {
		// TODO deallocateIP hern
		return fmt.Errorf("Failed to allocate IP address for a pod %s.%s, err=(%s)", k8sargs.K8S_POD_NAMESPACE, currentTenant.Name, err)
	}
	log.Infof("Allocated IP address %s", ipamResp.Ip)
	ipamIP, err := netlink.ParseIPNet(ipamResp.Ip + "/32")
	if err != nil {
		// TODO deallocateIP hern
		return fmt.Errorf("Failed to parse IP address %s, err=(%s)", ipamResp.Ip, err)
	}

	result := &current.Result{
		IPs: []*current.IPConfig{
			&current.IPConfig{
				Version:   "4",
				Address:   *ipamIP,
				Interface: 0,
			},
		},
	}

	// Networking setup
	_, gwAddr, err := getRomanaGwAddr()
	if err != nil {
		// TODO deallocateIP hern
		return fmt.Errorf("Failed to detect ipv4 address on romana-gw interface, err=(%s)", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		// TODO deallocateIP hern
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	contIface := &current.Interface{}
	hostIface := &current.Interface{}
	ifName := "eth0"
	mtu := 1500 //TODO for stas, make configurable
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")

	err = netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}
		transportRoute := netlink.Route{
			LinkIndex: containerVeth.Index,
			Dst:       gwAddr,
		}
		log.Infof("About to add network route %s to link %d", transportRoute, containerVeth.Index)
		err = netlink.RouteAdd(&transportRoute)
		if err != nil {
			return nil
		}

		defaultRoute := netlink.Route{
			Dst: defaultNet,
			Gw:  gwAddr.IP,
		}
		log.Infof("About to add network route %s", defaultRoute)
		err = netlink.RouteAdd(&defaultRoute)
		if err != nil {
			return nil
		}

		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	})
	if err != nil {
		// TODO deallocateIP hern
		return fmt.Errorf("Failed to create veth interfaces in namespace %v, err=(%s)", netns, err)
	}
	err = ip.RenameLink(hostIface.Name, k8sargs.makeVethName())
	if err != nil {
		// TODO deallocateIP hern
		return fmt.Errorf("Failed to rename host part of veth interface from %s to %s, err=(%s)", hostIface.Name, k8sargs.makeVethName(), err)
	}

	result.Interfaces = []*current.Interface{hostIface}

	return types.PrintResult(result, cniVersion)
}

func getRomanaGwAddr() (netlink.Link, *net.IPNet, error) {
	const gwIface = "romana-gw"
	romanaGw, err := netlink.LinkByName(gwIface)
	if err != nil {
		return nil, nil, err
	}

	addr, err := netlink.AddrList(romanaGw, netlink.FAMILY_V4)
	if err != nil {
		return nil, nil, err
	}

	if len(addr) != 1 {
		return nil, nil, fmt.Errorf("Expected exactly 1 ipv4 address on romana-gw interface, found %d", len(addr))
	}

	return romanaGw, addr[0].IPNet, nil
}

func deallocatePodIP(client *common.RestClient, k8sargs K8sArgs) error {
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

	targetName := k8sargs.makePodName()

	for eNum, endpoint := range endpoints {
		if endpoint.Name == targetName && endpoint.InUse {
			podEndpoints = append(podEndpoints, endpoints[eNum])
		}
	}

	if len(podEndpoints) == 0 {
		return fmt.Errorf("No IPAM endpoints found for pod %s", targetName)
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

func cmdDel(args *skel.CmdArgs) error {
	var result *current.Result
	var err error
	// Stdin args have romana related config.
	// Loaded via loadConf into NetConf.
	netConf, _, _ := loadConf(args.StdinData)
	cniVersion := netConf.CNIVersion

	// environment variables have CNI related config (CNI_COMMAND, CNI_IFNAME, CNI_NETNS, CNI_CONTAINERID, CNI_PATH, CNI_ARGS).
	// Loaded via skel.getCmdAgrsFromEnv into skel.CmdArgs

	// CNI_ARGS contain additional K8S config (IP, K8S_POD_NAME, K8S_POD_NAMESPACE, K8S_POD_INFRA_CONTAINER_ID, IgnoreUnknown)
	// Laded via cni.types.LoadArgs into  K8sArgs
	k8sargs := K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sargs)
	if err != nil {
		return err
	}

	// Rest client config
	clientConfig := common.GetDefaultRestClientConfig(netConf.RomanaRoot, nil)
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		return fmt.Errorf("Failed to reach romana root at %s, err=(%s)", netConf.RomanaRoot, err)
	}
	log.Infof("Created romana client %v", client)

	err = deallocatePodIP(client, k8sargs)
	if err != nil {
		return fmt.Errorf("Failed to tear down pod network for %s, err=(%s)", k8sargs.makePodName(), err)
	}

	return types.PrintResult(result, cniVersion)
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
