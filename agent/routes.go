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

// package agent's this file contains all the necessary functions
// to bring up romana gateway, update necessary kernel parameters
// and then finally update routes needed by romana to successfully
// communicate between nodes in romana cluster.
package agent

import (
	"io/ioutil"
	"net"
	"syscall"
	"time"

	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"

	"github.com/vishvananda/netlink"
)

var (
	kernelDefaults = []string{
		"/proc/sys/net/ipv4/conf/default/proxy_arp",
		"/proc/sys/net/ipv4/conf/all/proxy_arp",
		"/proc/sys/net/ipv4/ip_forward",
	}
)

// createRomanaGW creates Romana Gateway and brings up the necessary
// configuration for it, for example: assign IP Address to it, etc.
func (a Agent) createRomanaGW() error {
	log.Trace(trace.Private, "In Agent createRomanaGW()")

	// Check below for more details about not using flags here.
	//rgw := &netlink.Dummy{
	//	LinkAttrs: netlink.LinkAttrs{
	//		Name:   "romana-gw",
	//		TxQLen: 1000,
	//		Flags:  net.FlagUp,
	//	},
	//}
	rgw := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "romana-gw", TxQLen: 1000}}
	if err := netlink.LinkAdd(rgw); err != nil {
		if err == syscall.EEXIST {
			log.Warn("romana gateway already exists.")
		} else {
			log.Info("Error adding romana gateway to node:", err)
			return err
		}
	} else {
		log.Info("Successfully added romana gateway to node.")
	}

	a.networkConfig.Lock()
	oldIP := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   a.networkConfig.oldRomanaGW,
			Mask: a.networkConfig.oldRomanaGWMask,
		},
	}
	if err := netlink.AddrDel(rgw, oldIP); err != nil {
		// Log error and continue as usual, since its ok if we can't delete
		// the old IPAddress, since we may have lost it due to multiple reasons.
		log.Warn("Error while removing old IPAddress from romana gateway:", err)
	}

	ip := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   a.networkConfig.romanaGW,
			Mask: a.networkConfig.romanaGWMask,
		},
	}
	err := netlink.AddrAdd(rgw, ip)
	a.networkConfig.Unlock()
	if err != nil {
		if err == syscall.EEXIST {
			log.Info("romana gateway already has the following IPAddress:", ip)
		} else {
			log.Error("Error while assigning IPAddress to romana gateway:", err)
			return err
		}
	} else {
		log.Info("Successfully assigned IPAddress to romana gateway:", ip)
	}

	// don't use Flags: net.FlagUp in &netlink.Dummy{netlink.LinkAttrs{}}
	// above, since romana gateway may already be present and will not come
	// up until LinkSetUp is called on it explicitly.
	if err := netlink.LinkSetUp(rgw); err != nil {
		log.Error("Error while brining up romana gateway:", err)
		return err
	}
	log.Info("Successfully brought up romana gateway.")
	return nil
}

// enableRomanaKernelDefaults enables default kernel settings needed by
// romana, for example: ip forward, proxy arp, etc
func (a Agent) enableRomanaKernelDefaults() error {
	log.Trace(trace.Private, "In Agent enableRomanaKernelDefaults()")

	for i, path := range kernelDefaults {
		if err := ioutil.WriteFile(path, []byte("1"), 0644); err != nil {
			log.Errorf("Error changing kernel parameter(%s): %s", path, err)
			return err
		}
		log.Debugf("%d: Succesfully enabled kernel parameter: %s", i, path)
	}

	log.Info("Successfully enabled kernel parameters for romana.")
	return nil
}

// routeUpdater polls romana topology service for route changes and
// updates routes accordingly.
func (a Agent) routeUpdater(stopRouteUpdater <-chan struct{}, routeRefreshSeconds int) error {
	log.Trace(trace.Private, "In Agent routeUpdater()")

	go a.routePopulate(stopRouteUpdater, routeRefreshSeconds)
	go a.routeSet(stopRouteUpdater, routeRefreshSeconds)

	return nil
}

// routePopulate populates a.networkConfig.otherHosts periodically after every
// routeRefreshSeconds after query topology service for changes in node list.
// TODO: Currently routePopulate polls topology service, convert this
// to kvstore watch on /romana/nodes once kvstore backend is ready.
func (a Agent) routePopulate(stop <-chan struct{}, routeRefreshSeconds int) {
	log.Trace(trace.Private, "In Agent routePopulate()")

	routeRefresh := time.Tick(time.Duration(routeRefreshSeconds) * time.Second)

	for {
		select {
		case <-routeRefresh:
			log.Trace(trace.Inside, "Populating routes from topology service now: ", time.Now())
			if err := a.identifyCurrentHost(); err != nil {
				log.Error("Agent routePopulate: ", err)
			}
			log.Debug("Agent routeSet updated routes successfully.")

		case <-stop:
			log.Info("Stopping Agent routePopulate() mechanism")
			return
		}
	}
}

// routeSet updates the routes/romana-gw and other network configs
// depending on the updates received to it form routePopulate above.
func (a Agent) routeSet(stop <-chan struct{}, routeRefreshSeconds int) {
	log.Trace(trace.Private, "In Agent routeSet()")

	// Delay routeSet() by few seconds till routePopulate() updates
	// routes from topology service.
	delay := time.Tick(time.Duration(routeRefreshSeconds/2) * time.Second)
	<-delay

	routeRefresh := time.Tick(time.Duration(routeRefreshSeconds) * time.Second)

	for {
		select {
		case <-routeRefresh:
			log.Trace(trace.Inside, "Refreshing routes on the node now: ", time.Now())
			if err := a.Helper.ensureInterHostRoutes(); err != nil {
				log.Error("Agent routeSet: ", err)
			}
			log.Debug("Agent routeSet updated routes successfully.")

		case <-stop:
			log.Info("Stopping Agent routeSet() mechanism")
			return
		}
	}
}
