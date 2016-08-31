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
	"strings"

	"github.com/romana/core/common"

	_ "github.com/go-sql-driver/mysql"
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
// for the given list of hostID's. This is mainly to
// reuse the hostID if the host gets deletes and use
// use the same subnet in process, since subnet is
// generated based on id as shown in getNetworkFromID.
func findFirstAvaiableID(arr []uint64) uint64 {
	for i := 0; i < len(arr)-1; i++ {
		if arr[i+1]-arr[i] > 1 {
			return arr[i] + 1
		}
	}
	return arr[len(arr)-1] + 1
}

// getNetworkFromID calculates a subnet equivalent to id
// specified, from the avaiable romana cidr.
// Currently only IPv4 is supported.
func getNetworkFromID(id uint64, hostBits uint) (string, error) {
	if id == 0 || id > uint64(1<<hostBits) {
		return "", fmt.Errorf("error: invalid id passed or max subnets already allocated.")
	}
	if hostBits >= 24 {
		return "", fmt.Errorf("error: invalid number of bits alloacted for hosts.")
	}

	var hostIP uint32 = 0x0A << hostBits
	hostIP += uint32(id) - 1
	hostIP <<= 24 - hostBits

	bufHostIP := new(bytes.Buffer)
	err := binary.Write(bufHostIP, binary.BigEndian, hostIP)
	if err != nil {
		return "", fmt.Errorf("error: subnet ip calculation (%s) failed.", err)
	}
	var hostIPNet net.IPNet
	for i := range hostIPNet.IP {
		hostIPNet.IP[i] = bufHostIP.Bytes()[i]
	}

	var hostMask uint32
	for i := uint(0); i < hostBits+8; i++ {
		hostMask |= 1 << i
	}
	hostMask <<= 24 - hostBits
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

func (topoStore *topoStore) addHost(dc *common.Datacenter, host *common.Host) error {
	var count uint
	db := topoStore.DbStore.Db.Count(&count)
	if db.Error != nil {
		return db.Error
	}
	err := common.MakeMultiError(topoStore.DbStore.Db.GetErrors())
	if err != nil {
		return err
	}
	if count >= 1<<dc.PortBits {
		return fmt.Errorf("error: max number (%d) of hosts exceeded.", count)
	}

	romanaIP := strings.TrimSpace(host.RomanaIp)
	if romanaIP == "" {
		tx := topoStore.DbStore.Db.Begin()

		var allHostsID []uint64
		if err := tx.Select("id").Find(&allHostsID).Error; err != nil {
			tx.Rollback()
			return err
		}

		id := findFirstAvaiableID(allHostsID)
		host.RomanaIp, err = getNetworkFromID(id, dc.PortBits)
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
		topoStore.DbStore.Db.NewRecord(*host)
		db := topoStore.DbStore.Db.Create(host)
		err := common.GetDbErrors(db)
		if err != nil {
			log.Printf("topology.store.addHost(%v): %v", host, err)
			return "", err
		}
	}
	return nil
}
