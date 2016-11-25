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

// Package topology host, TOR definitions.
package topology

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/romana/core/common"

	_ "github.com/go-sql-driver/mysql"
)

var (
	BITS_IN_BYTE uint = 8
)

type Tor struct {
	Id         uint64 `sql:"AUTO_INCREMENT"`
	datacenter *common.Datacenter
}

// Backing store
type topoStore struct {
	common.DbStore
}

func (topoStore *topoStore) Entities() []interface{} {
	retval := make([]interface{}, 2)
	retval[0] = &common.Host{}
	retval[1] = &common.Datacenter{}
	return retval
}

func (topoStore *topoStore) CreateSchemaPostProcess() error {
	return nil
}

func (topoStore *topoStore) findHost(id uint64) (common.Host, error) {
	host := common.Host{}
	topoStore.DbStore.Db.Where("id = ?", id).First(&host)
	err := common.MakeMultiError(topoStore.DbStore.Db.GetErrors())
	if err != nil {
		return host, err
	}
	return host, nil
}

func (topoStore *topoStore) listHosts() ([]common.Host, error) {
	var hosts []common.Host
	log.Println("In listHosts()")
	topoStore.DbStore.Db.Find(&hosts)
	err := common.MakeMultiError(topoStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	log.Println("listHosts(): found hosts:", hosts)
	return hosts, nil
}

// findFirstAvaiableID finds the first available ID
// for the given list of hostIDs. This is mainly to
// reuse the hostID if the host gets deleted and
// use the same subnet in process, since subnet is
// generated based on id as shown in getNetworkFromID.
func findFirstAvaiableID(arr []uint64) uint64 {
	if len(arr) == 0 {
		return 1
	}
	for i := 0; i < len(arr)-1; i++ {
		if arr[i+1]-arr[i] > 1 {
			return arr[i] + 1
		}
	}
	return arr[len(arr)-1] + 1
}

// getNetworkFromID calculates a subnet equivalent to id
// specified, from the avaiable romana cidr. Currently
// only IPv4 is supported.
func getNetworkFromID(id uint64, hostBits uint, cidr string) (string, error) {
	if id == 0 || id > uint64(1<<hostBits) {
		return "", fmt.Errorf("error: invalid id passed or max subnets already allocated.")
	}

	networkBits := strings.Split(cidr, "/")
	if len(networkBits) != 2 {
		return "", fmt.Errorf("error: parsing romana cidr (%s) failed.", cidr)
	}

	networkBits[0] = strings.TrimSpace(networkBits[0])
	romanaPrefix := net.ParseIP(networkBits[0])
	if romanaPrefix == nil {
		return "", fmt.Errorf("error: parsing romana cidr (%s) failed.", networkBits[0])
	}

	networkBits[1] = strings.TrimSpace(networkBits[1])
	romanaPrefixBits, err := strconv.ParseUint(networkBits[1], 10, 64)
	if err != nil {
		return "", fmt.Errorf("error: parsing romana cidr (%s) failed.", networkBits[1])
	}

	var romanaPrefixUint32 uint32
	byteRomanaPrefix := romanaPrefix.To4()
	bufRomanaPrefix := bytes.NewReader(byteRomanaPrefix)
	err = binary.Read(bufRomanaPrefix, binary.BigEndian, &romanaPrefixUint32)
	if err != nil {
		return "", fmt.Errorf("error: parsing romana cidr (%s) failed.", romanaPrefix)
	}

	// since this function is limited to IPv4, handle romanaPrefixBits accordingly.
	if hostBits >= (net.IPv4len*BITS_IN_BYTE - uint(romanaPrefixBits)) {
		return "", fmt.Errorf("error: invalid number of bits allocated for hosts.")
	}

	var hostIP uint32
	hostIP = (romanaPrefixUint32 >> (net.IPv4len*BITS_IN_BYTE - uint(romanaPrefixBits))) << hostBits
	hostIP += uint32(id) - 1
	hostIP <<= (net.IPv4len*BITS_IN_BYTE - uint(romanaPrefixBits)) - hostBits

	bufHostIP := new(bytes.Buffer)
	err = binary.Write(bufHostIP, binary.BigEndian, hostIP)
	if err != nil {
		return "", fmt.Errorf("error: subnet ip calculation (%s) failed.", err)
	}

	var hostIPNet net.IPNet
	hostIPNet.IP = make(net.IP, net.IPv4len)
	hostIPNet.Mask = make(net.IPMask, net.IPv4len)
	for i := range hostIPNet.IP {
		hostIPNet.IP[i] = bufHostIP.Bytes()[i]
	}

	var hostMask uint32
	for i := uint(0); i < hostBits+uint(romanaPrefixBits); i++ {
		hostMask |= 1 << i
	}
	hostMask <<= (net.IPv4len*BITS_IN_BYTE - uint(romanaPrefixBits)) - hostBits
	bufHostMask := new(bytes.Buffer)
	err = binary.Write(bufHostMask, binary.BigEndian, hostMask)
	if err != nil {
		return "", fmt.Errorf("error: subnet mask calculation (%s) failed.", err)
	}
	for i := range hostIPNet.Mask {
		hostIPNet.Mask[i] = bufHostMask.Bytes()[i]
	}

	return hostIPNet.String(), nil
}

// addHost adds a new host to a specific datacenter, it also makes sure
// that if a romana cidr is not assigned, then to create and assign a new
// romana cidr using help of helper functions like findFirstAvaiableID
// and getNetworkFromID.
func (topoStore *topoStore) addHost(dc *common.Datacenter, host *common.Host) error {
	romanaIP := strings.TrimSpace(host.RomanaIp)
	if romanaIP == "" {
		var err error
		tx := topoStore.DbStore.Db.Begin()

		var allHostsID []uint64
		if err := tx.Table("hosts").Pluck("id", &allHostsID).Error; err != nil {
			tx.Rollback()
			return err
		}

		id := findFirstAvaiableID(allHostsID)
		host.RomanaIp, err = getNetworkFromID(id, dc.PortBits, dc.Cidr)
		// TODO: auto generation of romana cidr doesn't handle previously
		//       allocated cidrs currently, thus it needs to be handled
		//       here so that no 2 hosts get same or overlapping cidrs.
		//       here check needs to be in place to detect all manually
		//       inserted romana cidrs for overlap.
		if err != nil {
			tx.Rollback()
			return err
		}

		if err := tx.Create(host).Error; err != nil {
			tx.Rollback()
			return err
		}
		tx.Commit()
	} else {
		// TODO: auto generation of romana cidr doesn't handle previously
		//       allocated cidrs currently, thus it needs to be handled
		//       here so that no 2 hosts get same or overlapping cidrs.
		//       here check needs to be in place that auto generated cidrs
		//       overlap with this manually assigned one or not.
		topoStore.DbStore.Db.NewRecord(*host)
		db := topoStore.DbStore.Db.Create(host)
		if err := common.GetDbErrors(db); err != nil {
			log.Printf("topology.store.addHost(%v): %v", host, err)
			return err
		}
	}
	return nil
}
