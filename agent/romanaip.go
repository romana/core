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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"syscall"

	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"

	"github.com/docker/libkv/store"
	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
)

func GetDefaultLink() (netlink.Link, error) {
	defaultR := netlink.Route{}

	routes, err := netlink.RouteList(nil, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("error finding default route: %s", err)
	}

	for _, r := range routes {
		// If dst/src is not specified for a route, then it
		// means a default route is found which handles packets
		// for everything which is not handled by specific routes.
		if r.Src == nil && r.Dst == nil {
			defaultR = r
			break
		}
	}

	// if default route is not found above, then we have
	// LinkIndex as zero, but LinkIndex start from one, so
	// this will error out, which should be the case, since
	// anyways we couldn't find default link, and other
	// links maybe lo, etc which can't be used and thus
	// error out and return below.
	link, err := netlink.LinkByIndex(defaultR.LinkIndex)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, errors.New("error, could not locate default link for host")
	}

	return link, nil
}

// GetIPs returns all the IPv4 Address attached to link.
func GetIPs(link netlink.Link) ([]string, error) {
	var addresses []string

	addrList, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("error finding IP adrress for link (%s): %s",
			link.Attrs().Name, err)
	}

	for _, addr := range addrList {
		addresses = append(addresses, addr.IP.String())
	}

	if len(addresses) < 1 {
		return nil, fmt.Errorf("error finding IP adrress for link (%s)",
			link.Attrs().Name)
	}

	return addresses, nil
}

func linkAddDeleteIP(kvpair *store.KVPairExt, toAdd bool,
	defaultLink netlink.Link, defaultLinkAddressList []string) error {
	var value string
	var IPAddressOnThisNode bool

	if kvpair == nil || (kvpair.Value == "" && kvpair.PrevValue == "") {
		return fmt.Errorf("error retrieving value from the event notification")
	}

	if kvpair.Value != "" {
		value = kvpair.Value
	} else if kvpair.PrevValue != "" {
		value = kvpair.PrevValue
	}

	exposedIP := api.ExposedIPSpec{}
	if err := json.Unmarshal([]byte(value), &exposedIP); err != nil {
		return fmt.Errorf("error retrieving value from the event notification: %s", err)
	}

	if exposedIP.NodeIPAddress == "" {
		return fmt.Errorf("error finding node IP Address for romanaIP")
	}

	if exposedIP.RomanaIP.IP == "" {
		return fmt.Errorf("romana IP error or romana IP not found")
	}

	for i := range defaultLinkAddressList {
		if defaultLinkAddressList[i] == exposedIP.NodeIPAddress {
			IPAddressOnThisNode = true
			break
		}
	}

	if !IPAddressOnThisNode {
		log.Info("romanaIP not for this node, skipping processing it")
		return nil
	}

	ipAddress, err := netlink.ParseAddr(exposedIP.RomanaIP.IP + "/32")
	if err != nil {
		return fmt.Errorf("error parsing romana IP: %s", err)
	}

	if toAdd {
		return netlink.AddrAdd(defaultLink, ipAddress)
	}
	return netlink.AddrDel(defaultLink, ipAddress)
}

func StartRomanaIPSync(ctx context.Context, store *client.Store,
	defaultLink netlink.Link) error {
	var err error

	if store == nil || ctx == nil || defaultLink == nil {
		return fmt.Errorf("error store/context or link empty")
	}

	defaultLinkAddressList, err := GetIPs(defaultLink)
	if err != nil {
		return fmt.Errorf("failed to get default link's IP address: %s\n", err)
	}
	if len(defaultLinkAddressList) < 1 {
		return fmt.Errorf("failed to get default link's IP address")
	}

	go romanaIPWatcher(ctx, store, defaultLink, defaultLinkAddressList)

	return nil
}

func romanaIPWatcher(ctx context.Context, store *client.Store,
	defaultLink netlink.Link, defaultLinkAddressList []string) {

	// TODO: event stream could be broken it store connection is
	// broken so add support for re-watching the events stream here.
	events, err := store.WatchTreeExt(client.DefaultEtcdPrefix+client.RomanaIPPrefix,
		ctx.Done())
	if err != nil {
		log.Error("Error watching kvstore romanaIP keys.")
		return
	}

	for {
		select {
		case pair := <-events:
			switch pair.Action {
			case "create", "set", "update", "compareAndSwap":
				log.Debugf("creating/updating romanaIP: %#v\n", pair)
				err := linkAddDeleteIP(pair, true, defaultLink, defaultLinkAddressList)
				if err != nil {
					log.Errorf("error adding romanaIP to the link: %s", err)
					continue
				}
			case "delete":
				if pair.Dir {
					// TODO: currently if the whole "/romana/romanaip" kvstore
					// directory is deleted, then we need to delete all romanaIPs,
					// but currently we do nothing here and handle only single
					// romanaIP deletion event below.
					log.Infof("should be deleting ALL romanaIPs(%#v) here, ignoring currently",
						pair)
				} else {
					log.Debugf("deleting romanaIP: %#v\n", pair)
					err := linkAddDeleteIP(pair, false, defaultLink, defaultLinkAddressList)
					if err != nil {
						log.Errorf("error deleting romanaIP from the link: %s", err)
						continue
					}
				}
			default:
				log.Infof("missed romanaIP event type: %s", pair.Action)
			}
		case <-ctx.Done():
			log.Printf("\nStopping romanaIP watcher module.\n")
			return
		}
	}
}
