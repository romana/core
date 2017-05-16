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

// Romana CNI plugin configures kubernetes pods on Romana network.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/romana/core/pkg/cni/kubernetes"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	util "github.com/romana/core/pkg/cni"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
)

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// cmdAdd is a callback functions that gets called by skel.PluginMain
// in response to ADD method.
func cmdAdd(args *skel.CmdArgs) error {
	var err error
	// netConf stores Romana related config
	// that comes form stdin.
	netConf, _, _ := loadConf(args.StdinData)
	cniVersion := netConf.CNIVersion
	log.Debugf("Loaded netConf %v", netConf)

	// LoadArgs parses kubernetes related parameters from CNI
	// environment variables.
	k8sargs := kubernetes.K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sargs)
	if err != nil {
		return fmt.Errorf("Failed to types.LoadArgs, err=(%s)", err)
	}
	log.Debugf("Loaded Kubernetes args %v", k8sargs)

	// Retrieves additional information about the pod
	pod, err := kubernetes.GetPodDescription(k8sargs, netConf.KubernetesConfig)
	if err != nil {
		return err
	}

	// Deferring deallocation before allocating ip address,
	// deallocation will be called on any return unless
	// flag set to false.
	var deallocateOnExit = true
	defer func() {
		if deallocateOnExit {
			deallocator, err := util.NewRomanaAddressManager(util.DefaultProvider)

			// don't want to panic here
			if netConf != nil && err == nil {
				log.Errorf("Deallocating IP on exist, something went wrong")
				_ = deallocator.Deallocate(*netConf, pod.Name)
			}
		}
	}()

	// Allocating ip address.
	allocator, err := util.NewRomanaAddressManager(util.DefaultProvider)
	if err != nil {
		return err
	}
	podAddress, err := allocator.Allocate(*netConf, util.RomanaAllocatorPodDescription{
		Name:        pod.Name,
		Hostname:    netConf.RomanaHostName,
		Namespace:   pod.Namespace,
		Labels:      pod.Labels,
		Annotations: pod.Annotations,
	})
	if err != nil {
		return err
	}

	// Networking setup
	_, gwAddr, err := GetRomanaGwAddr()
	if err != nil {
		return fmt.Errorf("Failed to detect ipv4 address on romana-gw interface, err=(%s)", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// Magic variables for callback.
	contIface := &current.Interface{}
	hostIface := &current.Interface{}
	ifName := "eth0"
	mtu := 1500 //TODO for stas, make configurable
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")

	// And this is a callback inside the callback, it sets up networking
	// withing a pod namespace, nice thing it save us from shellouts
	// but still, callback within a callback.
	err = netns.Do(func(hostNS ns.NetNS) error {
		// Creates veth interfacces.
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}

		// transportNet is a romana-gw cidr turned into romana-gw.IP/32
		transportNet := net.IPNet{IP: gwAddr.IP, Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff})}
		transportRoute := netlink.Route{
			LinkIndex: containerVeth.Index,
			Dst:       &transportNet,
		}

		// sets up transport route to allow installing default route
		err = netlink.RouteAdd(&transportRoute)
		if err != nil {
			return fmt.Errorf("route add error=(%s)", err)
		}

		// default route for the pod
		defaultRoute := netlink.Route{
			Dst:       defaultNet,
			LinkIndex: containerVeth.Index,
		}
		err = netlink.RouteAdd(&defaultRoute)
		if err != nil {
			return fmt.Errorf("route add default error=(%s)", err)
		}

		containerVethLink, err := netlink.LinkByIndex(containerVeth.Index)
		if err != nil {
			return fmt.Errorf("failed to discover container veth, err=(%s)", err)
		}

		podIP, err := netlink.ParseAddr(podAddress.String())
		if err != nil {
			return fmt.Errorf("netlink failed to parse address %s, err=(%s)", podAddress, err)
		}

		err = netlink.AddrAdd(containerVethLink, podIP)
		if err != nil {
			return fmt.Errorf("failed to add ip address %s to the interface %s, err=(%s)", podIP, containerVeth, err)
		}

		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	})
	if err != nil {
		return fmt.Errorf("Failed to create veth interfaces in namespace %v, err=(%s)", netns, err)
	}

	// Rename host part of veth to something convinient.
	vethExternalName := k8sargs.MakeVethName()
	err = RenameLink(hostIface.Name, vethExternalName)
	if err != nil {
		return fmt.Errorf("Failed to rename host part of veth interface from %s to %s, err=(%s)", hostIface.Name, vethExternalName, err)
	}

	// Return route.
	err = AddEndpointRoute(vethExternalName, podAddress)
	if err != nil {
		return fmt.Errorf("Failed to setup return route to %s via interface %s, err=(%s)", podAddress, hostIface.Name, err)
	}

	result := &current.Result{
		IPs: []*current.IPConfig{
			&current.IPConfig{
				Version:   "4",
				Address:   *podAddress,
				Interface: 0,
			},
		},
	}

	result.Interfaces = []*current.Interface{hostIface}

	deallocateOnExit = false
	return types.PrintResult(result, cniVersion)
}

// cmdDel is a callback functions that gets called by skel.PluginMain
// in response to DEL method.
func cmdDel(args *skel.CmdArgs) error {
	var err error
	// netConf stores Romana related config
	// that comes form stdin.
	netConf, _, _ := loadConf(args.StdinData)

	// LoadArgs parses kubernetes related parameters from CNI
	// environment variables.
	k8sargs := kubernetes.K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sargs)
	if err != nil {
		return err
	}

	deallocator, err := util.NewRomanaAddressManager(util.DefaultProvider)
	if err != nil {
		return err
	}
	err = deallocator.Deallocate(*netConf, k8sargs.MakePodName())
	if err != nil {
		return fmt.Errorf("Failed to tear down pod network for %s, err=(%s)", k8sargs.MakePodName(), err)
	}

	return nil
}

// GetRomanaGwAddr detects ip address assigned to romana-gw interface.
func GetRomanaGwAddr() (netlink.Link, *net.IPNet, error) {
	const gwIface = "romana-gw"
	romanaGw, err := netlink.LinkByName(gwIface)
	if err != nil {
		return nil, nil, err
	}

	addr, err := netlink.AddrList(romanaGw, syscall.AF_INET)
	if err != nil {
		return nil, nil, err
	}

	if len(addr) != 1 {
		return nil, nil, fmt.Errorf("Expected exactly 1 ipv4 address on romana-gw interface, found %d", len(addr))
	}

	return romanaGw, addr[0].IPNet, nil
}

// RenameLink renames interface.
func RenameLink(curName, newName string) error {
	curVeth, err := netlink.LinkByName(curName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", curName, err)
	}

	if err = netlink.LinkSetDown(curVeth); err != nil {
		return fmt.Errorf("failed to set %q up: %v", curName, err)
	}

	err = netlink.LinkSetName(curVeth, newName)
	if err != nil {
		return fmt.Errorf("failed to rename %q: %v", curVeth, newName)
	}

	newVeth, err := netlink.LinkByName(newName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", newName, err)
	}

	err = netlink.LinkSetUp(newVeth)
	if err != nil {
		return fmt.Errorf("failed to set %q up: %v", newVeth, err)
	}

	return nil
}

// AddEndpointRoute adds return /32 route from host to pod.
func AddEndpointRoute(ifaceName string, ip *net.IPNet) error {
	veth, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	returnRoute := netlink.Route{
		Dst:       ip,
		LinkIndex: veth.Attrs().Index,
	}

	err = netlink.RouteAdd(&returnRoute)

	return nil
}

// loadConf initializes romana config from stdin.
func loadConf(bytes []byte) (*util.NetConf, string, error) {
	n := &util.NetConf{}
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

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
