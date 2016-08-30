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
package kvstore

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/romana/core/common"
	log "github.com/romana/rlog"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/etcd"
)

var (
	KVStore           store.Store
	connectionTimeout = 10 * time.Second
	endpoints         = []string{"192.168.99.10:2379"}
)

// Initialize etcd backends for libkv
func init() {
	// Register etcd store to libkv
	etcd.Register()

	// Initialize a new store with etcd
	var err error
	KVStore, err = libkv.NewStore(
		store.ETCD,
		endpoints,
		&store.Config{
			ConnectionTimeout: connectionTimeout,
		},
	)

	// TODO: add config support and move new store
	//       init to its own function, until then
	//       fail if etcd is not available.
	if err != nil {
		log.Critical("Cannot create etcd store")
		return os.Exit(254)
	}
}

func AddHost(host *common.Host) error {
	if host.ID == 0 {
		return fmt.Errorf("error: hostID not present, can't add new host details.")
	}
	key := "/romana/network/hosts/" + strconv.FormatUint(host.ID, 10)
	value, err := json.Marshal(host)
	if err != nil {
		log.Error("error converting host data to json:")
		log.Trace(5, err)
		log.Trace(5, "host: ", host)
		return err
	}
	err = KVStore.Put(key, value, nil)
	if err != nil {
		log.Error("error storing kv pair for host.")
		log.Trace(5, err)
		log.Trace(5, "key: ", key)
		log.Trace(5, "value: ", value)
		return err
	}
	return nil
}

func DeleteHost(hostID uint64) error {
	if hostID == 0 {
		return fmt.Errorf("error deleting host, hostID not present.")
	}
	key := "/romana/network/hosts/" + strconv.FormatUint(hostID, 10)
	err := KVStore.Delete(key)
	if err != nil {
		log.Error("error storing kv pair for host.")
		log.Trace(5, err)
		log.Trace(5, "key: ", key)
		return err
	}
	return nil
}
