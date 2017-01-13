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

// Package kvstore provides a flexible key value backend to be used
// with romana servies based of on docker/libkv.
package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/romana/core/common"
	log "github.com/romana/rlog"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	BITS_IN_BYTE uint = 8
)

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

// GetStore is a factory method, returning the appropriate store provided
// the config.
func GetStore(configMap map[string]interface{}) (common.Store, error) {
	config, err := common.MakeStoreConfig(configMap)
	if err != nil {
		return nil, err
	}
	var store common.Store
	switch config.Type {
	default:
		return nil, common.NewError("Unknown store type: '%s'", config.Type)
	case common.StoreTypeMysql, common.StoreTypeSqlite3:
		rdbmsStore := &RdbmsStore{}
		rdbmsStore.ServiceStore = rdbmsStore
		rdbmsStore.DbStore.ServiceStore = rdbmsStore
		store = rdbmsStore
	case common.StoreTypeEtcd:
		store = &KvStore{}
	}
	store.SetConfig(config)
	return store, nil
}

// createSchemaSqlite3 creates schema for a sqlite3 db
func createSchemaSqlite3(dbStore *DbStore, force bool) error {
	schemaName := dbStore.Config.Database
	log.Infof("Entering createSchemaSqlite3() with %s", schemaName)
	var err error
	if force {
		finfo, err := os.Stat(schemaName)
		exist := finfo != nil || os.IsExist(err)
		log.Infof("Before attempting to drop %s, exists: %t, stat: [%v] ... [%v]", schemaName, exist, finfo, err)
		if exist {
			err = os.Remove(schemaName)
			if err != nil {
				return err
			}
		}
	}
	err = dbStore.Connect()
	if err != nil {
		return err
	}

	entities := dbStore.ServiceStore.Entities()
	log.Infof("Creating tables for %v", entities)
	for _, entity := range entities {
		log.Infof("sqlite3: Creating table for %T", entity)
		db := dbStore.Db.CreateTable(entity)
		if db.Error != nil {
			return db.Error
		}
	}

	errs := dbStore.Db.GetErrors()
	log.Infof("sqlite3: Errors: %v", errs)
	err2 := common.MakeMultiError(errs)

	if err2 != nil {
		return err2
	}
	return dbStore.ServiceStore.CreateSchemaPostProcess()
}

// createSchemaMysql creates schema for a MySQL db
func createSchemaMysql(dbStore *DbStore, force bool) error {
	log.Infof("in createSchema(%t)", force)

	schemaName := dbStore.Config.Database
	dbStore.Config.Database = "mysql"
	err := dbStore.Connect()
	if err != nil {
		return err
	}

	db := dbStore.Db
	var sql string
	if force {
		sql = fmt.Sprintf("DROP DATABASE IF EXISTS %s", schemaName)
		db.Exec(sql)
	}

	sql = fmt.Sprintf("CREATE DATABASE %s CHARACTER SET ascii COLLATE ascii_general_ci", schemaName)
	db.Exec(sql)
	err = common.MakeMultiError(db.GetErrors())
	if err != nil {
		return err
	}

	dbStore.Config.Database = schemaName
	err = dbStore.Connect()
	if err != nil {
		return err
	}

	entities := dbStore.ServiceStore.Entities()

	for i := range entities {
		entity := entities[i]
		db := dbStore.Db.CreateTable(entity)
		if db.Error != nil {
			return db.Error
		}
	}
	err = common.MakeMultiError(dbStore.Db.GetErrors())
	if err != nil {
		return err
	}
	return dbStore.ServiceStore.CreateSchemaPostProcess()
}
