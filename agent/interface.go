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

	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func CreateRomanaGW() error {
	rgw := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "romana-lo", TxQLen: 1000}}
	if err := netlink.LinkAdd(rgw); err != nil {
		if err == unix.EEXIST {
			log.Warn("Romana gateway already exists.")
		} else {
			log.Info("Error adding Romana gateway to node:", err)
			return err
		}
	} else {
		log.Info("Successfully added romana gateway to node.")
	}

	if err := netlink.LinkSetUp(rgw); err != nil {
		log.Error("Error while brining up romana gateway:", err)
		return err
	}

	return nil
}

func SetRomanaGwIP(romanaIp string) error {
	nip := net.ParseIP(romanaIp)
	if nip == nil {
		return fmt.Errorf("Failed to parse ip address %s", romanaIp)
	}

	ipnet := &net.IPNet{IP: nip, Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff})}

	link, err := netlink.LinkByName("romana-lo")
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		if addr.IPNet.String() == ipnet.String() {
			log.Debugf("Address %s already installed in interface %s", addr, link)
			return nil
		}
	}

	ip := &netlink.Addr{
		IPNet: ipnet,
	}

	err = netlink.AddrAdd(link, ip)
	if err != nil {
		return err
	}

	return nil
}
