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
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/romana/core/common"

	_ "github.com/go-sql-driver/mysql"
)

var (
	MaxHostID  uint   = 1 << 8
	RomanaCIDR string = "10.0.0.0/8"
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
func getNetworkFromID(id uint64) (string, error) {
	// Currently only IPv4 is supported with romana host bits as 8.
	if id == 0 || id > uint64(MaxHostID) {
		return "", fmt.Errorf("error: invalid id passed or max subnets already allocated.")
	}
	_, net, err := net.ParseCIDR(RomanaCIDR)
	if err != nil {
		return "", err
	}
	net.IP[1] = byte(id - 1)
	net.Mask[1] = 0xff
	return net.String(), nil
}

func (topoStore *topoStore) addHost(host *common.Host) (string, error) {
	var err error

	// TODO: add support for testing datacenter host bits
	//       for overflow here, currently it can't be
	//       done because on k8s we don't support dc
	//       host bits yet, so check for 8 bits for
	//       now (i.e 255 max hosts).
	var count uint
	db := topoStore.DbStore.Db.Count(&count)
	if db.Error != nil {
		return "", db.Error
	}
	err = common.MakeMultiError(topoStore.DbStore.Db.GetErrors())
	if err != nil {
		log.Printf("topology.store.addHost(%v): %v", host, err)
		return "", err
	}
	if count >= MaxHostID {
		return "", fmt.Errorf("error: max number (%d) host exceeded.", count)
	}

	romanaIP := strings.TrimSpace(host.RomanaIp)
	if romanaIP == "" {
		tx := topoStore.DbStore.Db.Begin()

		var allHostsID []uint64
		if err := tx.Select("id").Find(&allHostsID).Error; err != nil {
			tx.Rollback()
			return "", err
		}

		id := findFirstAvaiableID(allHostsID)
		host.RomanaIp, err = getNetworkFromID(id)
		if err != nil {
			tx.Rollback()
			return "", err
		}

		if err := tx.Create(host).Error; err != nil {
			tx.Rollback()
			return "", err
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
	return strconv.FormatUint(host.ID, 10), nil
}
