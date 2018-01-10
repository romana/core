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
package cni

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

const (
	DefaultCNILogFile     = "/var/log/romana/cni.log"
	AlternativeCNILogFile = "/var/tmp/romana-cni.log"
)

// cmdAdd is a callback functions that gets called by skel.PluginMain
// in response to ADD method.
func CmdAdd(args *skel.CmdArgs) error {
	var err error
	// netConf stores Romana related config
	// that comes form stdin.
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}
	cniVersion := netConf.CNIVersion
	log.Debugf("Loaded netConf %v", netConf)

	// LoadArgs parses kubernetes related parameters from CNI
	// environment variables.
	k8sargs := K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sargs)
	if err != nil {
		return fmt.Errorf("Failed to types.LoadArgs, err=(%s)", err)
	}
	log.Debugf("Loaded Kubernetes args %v", k8sargs)

	// Retrieves additional information about the pod
	pod, err := GetPodDescription(k8sargs, netConf.KubernetesConfig)
	if err != nil {
		return err
	}

	var podAddress *net.IPNet
	romanaClient, err := MakeRomanaClient(netConf)
	if err != nil {
		return err
	}
	startTime := time.Now()
	log.Tracef(4, "Process %d started IPAM transaction at %s", os.Getpid(), startTime)
	defer func() {
		stopTime := time.Now()
		log.Tracef(4, "Process %d commited IPAM transaction at %s after %s, allocated %s", os.Getpid(), stopTime, stopTime.Sub(startTime), podAddress)
	}()

	// Deferring deallocation before allocating ip address,
	// deallocation will be called on any return unless
	// flag set to false.
	var deallocateOnExit = true
	defer func() {
		if deallocateOnExit {
			deallocator, err := NewRomanaAddressManager(DefaultProvider)

			// don't want to panic here
			if netConf != nil && err == nil {
				log.Errorf("Deallocating IP on exit, something went wrong")
				_ = deallocator.Deallocate(*netConf, romanaClient, pod.Name)
			}
		}
	}()

	// Allocating ip address.
	allocator, err := NewRomanaAddressManager(DefaultProvider)
	if err != nil {
		return err
	}
	podAddress, err = allocator.Allocate(*netConf, romanaClient, RomanaAllocatorPodDescription{
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
	gwAddr := &net.IPNet{IP: net.ParseIP("172.142.0.1"), Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff})}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// Magic variables for callback.
	contIface := &current.Interface{}
	hostIface := &current.Interface{}
	ifName := "eth0"
	mtu := 1500
	if netConf.MTU > 0 {
		mtu = netConf.MTU
	}
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")

	// And this is a callback inside the callback, it sets up networking
	// withing a pod namespace, nice thing it save us from shellouts
	// but still, callback within a callback.
	err = netns.Do(func(hostNS ns.NetNS) error {
		// Creates veth interfacces.
		hostVeth, containerVeth, err := SetupVeth(ifName, k8sargs.MakeVethName(), mtu, hostNS)
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
			return fmt.Errorf("failed to add ip address %s to the interface %s, err=(%s)", podIP, containerVeth.Name, err)
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

	// set proxy_delay to zero
	err = ioutil.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostIface.Name), []byte("0"), 0)
	if err != nil {
		// this is an optimization, so errors are logged, but don't result in failure
		log.Infof("Failed to set proxy_delay for %s, err=(%s)", hostIface.Name, err)
	}

	// Return route.
	err = AddEndpointRoute(hostIface.Name, podAddress, nil)
	if err != nil {
		log.Debug(err)
		return err
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

	if netConf.Policy {
		err := enablePodPolicy(k8sargs.MakeVethName())
		if err != nil {
			log.Errorf("Failed to hook pod %s to Romana policy, err=%s", k8sargs.MakePodName(), err)
			return err
		}
		log.Debugf("Pod rules created")
	}

	deallocateOnExit = false
	return types.PrintResult(result, cniVersion)
}

// cmdDel is a callback functions that gets called by skel.PluginMain
// in response to DEL method.
func CmdDel(args *skel.CmdArgs) error {
	// It only make sense to report retriable errors
	// back to kubernetes when deleting a pod
	// otherwise it will be stuck in deallocation loop forever.
	var err error

	// netConf stores Romana related config
	// that comes form stdin.
	netConf, err := loadConf(args.StdinData)
	if err != nil {
		log.Errorf("Pod deletion failed, can't load CNI config, %s", err)
		return nil
	}

	// LoadArgs parses kubernetes related parameters from CNI
	// environment variables.
	k8sargs := K8sArgs{}
	err = types.LoadArgs(args.Args, &k8sargs)
	if err != nil {
		log.Errorf("Pod deletion failed, can't parse kubernetes arguments, %s", err)
		return nil
	}

	romanaClient, err := MakeRomanaClient(netConf)
	if err != nil {
		log.Errorf("Pod %s deletion failed, can't make romana client, %s", k8sargs.MakePodName(), err)
		return nil
	}

	deallocator, err := NewRomanaAddressManager(DefaultProvider)
	if err != nil {
		log.Errorf("Pod %s deletion failed, can't deallocate ip address, %s", k8sargs.MakePodName(), err)
		return nil
	}

	err = deallocator.Deallocate(*netConf, romanaClient, k8sargs.MakePodName())
	if err != nil {
		log.Errorf("Failed to tear down pod network for %s, err=(%s)", k8sargs.MakePodName(), err)
		return nil
	}

	if netConf.Policy {
		err := disablePodPolicy(k8sargs.MakeVethName())
		if err != nil {
			log.Errorf("Failed to cleanup policy rules for pod %s, err=%s", k8sargs.MakePodName(), err)
			return nil
		}
		log.Debugf("Deleted pod rules")
	}

	return nil
}

type nlRouteHandle interface {
	LinkByName(name string) (netlink.Link, error)
	RouteAdd(*netlink.Route) error
	RouteReplace(*netlink.Route) error
	RouteGet(net.IP) ([]netlink.Route, error)
	Delete()
}

// AddEndpointRoute adds return /32 route from host to pod.
// This function is designed to take nil as nlRouteHandle argument.
func AddEndpointRoute(ifaceName string, ip *net.IPNet, nl nlRouteHandle) error {
	if nl == nil {
		var nlErr error
		nl, nlErr = netlink.NewHandle()
		if nlErr != nil {
			return fmt.Errorf("couldn't create netlink handle, err=(%s)", nlErr)
		}
		defer nl.Delete()
	}

	veth, err := nl.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	returnRoute := netlink.Route{
		Dst:       ip,
		LinkIndex: veth.Attrs().Index,
	}

	err = nl.RouteAdd(&returnRoute)
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if !ok {
			return fmt.Errorf("couldn't create route to %s via interface %s, err=(%s.(%T))",
				ip, ifaceName, err, err)
		}

		if errno != unix.EEXIST {
			return fmt.Errorf("couldn't create route to %s via interface %s, err=(%s)",
				ip, ifaceName, err)
		}

		// ignoring the error since this exists
		// for logging purposes only.
		origRoutes, _ := nl.RouteGet(ip.IP)

		// In case interface exists but isn't
		// pointing to the right interface.
		err2 := nl.RouteReplace(&returnRoute)
		if err2 != nil {
			return fmt.Errorf("couldn't replace route to %s via interface %s, err=(%s)",
				ip, ifaceName, err)
		}

		log.Debugf("successfully redirected network %s from %v to %s", ip, origRoutes, ifaceName)
	}

	return nil
}

// loadConf initializes romana config from stdin.
func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %s", err)
	}

	setLogOutput(n.LogFile)

	// TODO for stas
	// verify config here
	if n.RomanaHostName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to load netconf: %s", err)
		}

		n.RomanaHostName = hostname
	}

	return n, nil
}

// SetLogOutput sets the log output to a file named
// /var/log/romana/cni.log or if it is not accessible then
// /var/tmp/romana-cni.log
func setLogOutput(outputLogFile string) {
	var err error
	var logFile *os.File

	if outputLogFile == "" {
		outputLogFile = DefaultCNILogFile
	}

	logFile, err = os.OpenFile(outputLogFile,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logFile, err = os.OpenFile(AlternativeCNILogFile,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	}

	if err == nil {
		log.SetOutput(io.MultiWriter(logFile, os.Stderr))
	}
}
