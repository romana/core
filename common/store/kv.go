// Copyright (c) 2016-2017 Pani Networks
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

// Package store provides a flexible key value backend to be used
// with Romana services based of on docker/libkv.
package store

import (
	"encoding/json"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
	"net/url"
	"reflect"

	"strings"
	"time"

	"github.com/docker/libkv"
	libkvStore "github.com/docker/libkv/store"
	"github.com/docker/libkv/store/etcd"
)

const (
	DefaultConnectionTimeout = 10 * time.Second
)

// RomanaLibkvStore enhances libkv.store.Store with some operations
// useful for Romana
type RomanaLibkvStore struct {
	// Prefix for keys
	Prefix string
	libkvStore.Store
}

// KvStore is a structure storing information specific to KV-based
// implementation of Store.
type KvStore struct {
	Config *common.StoreConfig
	Db     RomanaLibkvStore
}

// Find generically implements Find() of Store interface
// for KvStore.
func (kvStore *KvStore) Find(query url.Values, entities interface{}, flag common.FindFlag) (interface{}, error) {
	// TODO this is intended as a temporary fix for CNI that looks for
	// host based on name. A more generic solution will come later.

	ptrToArrayType := reflect.TypeOf(entities)
	arrayType := ptrToArrayType.Elem()
	newEntities := reflect.New(arrayType).Interface()
	t := reflect.TypeOf(newEntities).Elem().Elem()
	hostType := reflect.TypeOf(common.Host{})
	if t.Name() != hostType.Name() {
		return nil, common.NewError500(fmt.Sprintf("Cannot look for %s", t.Name()))
	}
	hostName := query.Get("name")
	if flag != common.FindLast {
		return nil, common.NewError500(fmt.Sprintf("Unsupported flag %s", flag))
	}

	key := kvStore.makeKey("hosts")
	log.Debugf("KvStore.Find(): Made key %s from %s", key, t.Name())

	kvPairs, err := kvStore.Db.List(key)
	if kvPairs == nil || len(kvPairs) == 0 {
		return nil, common.NewError404("host", fmt.Sprintf("name=%s", hostName))
	}

	var goodHost *common.Host
	for _, kvPair := range kvPairs {
		curHost := &common.Host{}
		err = json.Unmarshal(kvPair.Value, curHost)
		if err != nil {
			return nil, err
		}
		log.Printf("Checking %s against %s", curHost.Name, hostName)
		if curHost.Name == hostName {
			goodHost = curHost
		}
	}
	if goodHost == nil {
		return nil, common.NewError404("name", hostName)
	}
	return *goodHost, nil
}

// SetConfig sets the config object from a map.
func (kvStore *KvStore) SetConfig(config common.StoreConfig) error {
	kvStore.Config = &config
	return nil
}

// Connect connects to the appropriate DB (mutating dbStore's state with
// the connection information), or returns an error.
func (kvStore *KvStore) Connect() error {
	var err error
	if kvStore.Config.Type != common.StoreTypeEtcd {
		return common.NewError("Unknown type: %s", kvStore.Config.Type)
	}
	endpoints := []string{fmt.Sprintf("%s:%d", kvStore.Config.Host, kvStore.Config.Port)}

	kvStore.Db = RomanaLibkvStore{Prefix: kvStore.Config.Database}
	kvStore.Db.Store, err = libkv.NewStore(
		libkvStore.ETCD,
		endpoints,
		&libkvStore.Config{
			ConnectionTimeout: DefaultConnectionTimeout,
		},
	)
	if err != nil {
		return err
	}

	return err
}

// reclaimID returns the ID into the pool.
func (kvStore *KvStore) reclaimID(key string, id uint64) error {
	lockKey := fmt.Sprintf("%s_lock", key)
	lock, err := kvStore.Db.NewLock(lockKey, nil)
	if err != nil {
		return err
	}
	stopChan := make(chan struct{})
	ch, err := lock.Lock(stopChan)
	defer lock.Unlock()
	if err != nil {
		return err
	}

	select {
	default:
		idRingKvPair, err := kvStore.Db.Get(key)
		if err != nil {
			return err
		}
		idRing, err := common.DecodeIDRing(idRingKvPair.Value)
		if err != nil {
			return err
		}
		err = idRing.ReclaimID(id)
		if err != nil {
			return err
		}
		idRingBytes, err := idRing.Encode()
		if err != nil {
			return err
		}
		err = kvStore.Db.Put(key, idRingBytes, nil)
		if err != nil {
			return err
		}
		return nil
	case <-ch:
		return nil
	}

}

// getID returns the next sequential ID for the specified key.
func (kvStore *KvStore) getID(key string) (uint64, error) {
	log.Debugf("getID: %s", key)
	var id uint64
	lockKey := fmt.Sprintf("%s_lock", key)
	lock, err := kvStore.Db.NewLock(lockKey, nil)
	if err != nil {
		log.Errorf("getID: Error acquiring lock for %s: %s", lockKey, err)
		return 0, err
	}
	log.Debugf("getID: Acquired lock for %s", lockKey)
	stopChan := make(chan struct{})
	log.Debugf("getID: Attempting to lock")
	ch, err := lock.Lock(stopChan)
	if err != nil {
		log.Errorf("getID: Error locking lock %s: %s", lock, err)
		return 0, err
	}
	log.Debugf("getID: Locked.")

	// This really is just a defer of Unlock()
	// but wrapped in a function to add logging.
	defer func() {
		err := lock.Unlock()
		if err != nil {
			log.Errorf("getID: Error unlocking %s", lockKey)
		} else {
			log.Debugf("getID: Unlocked lock %s", lockKey)
		}
	}()
	log.Debugf("getID: Entering select")
	select {
	default:
		log.Debugf("getID: In default of select")
		log.Debugf("getID: Fetching %s", key)
		idRingKvPair, err := kvStore.Db.Get(key)
		log.Debugf("getID: Got %v", *idRingKvPair)
		if err != nil {
			log.Debugf("getID: Error fetching %s: %s", key, err)
			return 0, err
		}
		log.Debugf("getID: Got %v", *idRingKvPair)
		idRing, err := common.DecodeIDRing(idRingKvPair.Value)
		if err != nil {
			return 0, err
		}
		log.Debugf("getID: Got %s", idRing)
		id, err = idRing.GetID()
		if err != nil {
			return 0, err
		}
		idRingBytes, err := idRing.Encode()
		if err != nil {
			return 0, err
		}
		err = kvStore.Db.Put(key, idRingBytes, nil)
		if err != nil {
			return 0, err
		}
		return id, nil
	case msg := <-ch:
		log.Debugf("getID: Received from channel: %s", msg)
		return id, nil
	}
}

// CreateSchema creates the schema in this DB. If force flag
// is specified, the schema is dropped and recreated.
func (kvStore *KvStore) CreateSchema(force bool) error {
	log.Debugf("Creating schema for %s", kvStore.Config.Database)
	err := kvStore.Connect()
	if err != nil {
		return err
	}
	toInit := []string{"hosts_ids", "tenant_ids", "segment_ids"}
	for _, s := range toInit {
		key := kvStore.makeKey(s)
		ring := common.NewIDRing()
		data, err := ring.Encode()
		if err != nil {
			return err
		}
		log.Debugf("CreateSchema: Putting %s into %s", ring, key)
		err = kvStore.Db.Put(key, data, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// makeKey returns the key that:
// 1. starts with the prefix that is configured as database in store config
// 2. Ends with suffix.
// 3. If args are present, suffix is interpreted as a string into which
//    args can be substituted as in fmt.Sprintf
func (kvStore *KvStore) makeKey(suffix string, args ...interface{}) string {
	if args != nil && len(args) > 0 {
		suffix = fmt.Sprintf(suffix, args...)
	}
	key := fmt.Sprintf("/%s/%s", kvStore.Config.Database, suffix)
	key = libkvStore.Normalize(key)
	key = strings.Replace(key, "//", "/", -1)
	return key
}

func (kvStore *KvStore) AddHost(dc common.Datacenter, host *common.Host) error {
	var err error
	hostsKey := kvStore.makeKey("hosts_ids")
	if host.ID == 0 {
		host.ID, err = kvStore.getID(hostsKey)
		if err != nil {
			log.Debugf("AddHost: Error getting new ID: %s", err)
			return err
		}
		log.Debugf("AddHost: Made ID %d", host.ID)
	}

	romanaIP := strings.TrimSpace(host.RomanaIp)
	if romanaIP == "" {
		host.RomanaIp, err = getNetworkFromID(host.ID, dc.PortBits, dc.Cidr)
		if err != nil {
			log.Debugf("AddHost: Error in getNetworkFromID: %s", err)
			return err
		}
	}
	key := kvStore.makeKey("hosts/%d", host.ID)
	value, err := json.Marshal(host)
	if err != nil {
		log.Debugf("AddHost: Error marshalling host: %s", err)
		return err
	}
	result, _, err := kvStore.Db.AtomicPut(key, value, nil, nil)
	if result {
		return nil
	}
	if err == libkvStore.ErrKeyExists {
		return common.NewErrorConflict(fmt.Sprintf("Host %d already exists: %v", host.ID, *host))
	} else {
		return err
	}
}

func (kvStore *KvStore) DeleteHost(hostID uint64) error {
	if hostID == 0 {
		return fmt.Errorf("error deleting host, hostID not present.")
	}

	key := kvStore.makeKey("hosts/%d", hostID)
	err := kvStore.Db.Delete(key)
	if err != nil {
		log.Debugf("DeleteHost: Error %s", err)
		return err
	}
	hostsKey := kvStore.makeKey("hosts_ids")
	err = kvStore.reclaimID(hostsKey, hostID)
	if err != nil {
		log.Debugf("DeleteHost: Error %s", err)
		return err
	}
	return nil
}

func (kvStore *KvStore) ListHosts() ([]common.Host, error) {
	log.Trace(trace.Public, "KvStore.ListHosts()")
	var err error
	key := kvStore.makeKey("hosts/")
	log.Debugf("ListHosts(): Listing %s", key)
	exists, err := kvStore.Db.Exists(key)
	if err != nil {
		log.Debugf("ListHosts: Error %s", err)
		return nil, err
	}
	if !exists {
		return make([]common.Host, 0), nil
	}
	list, err := kvStore.Db.List(key)

	if err != nil {
		log.Debugf("ListHosts: Error %s", err)
		return nil, err
	}
	hosts := make([]common.Host, len(list))
	for i, kv := range list {
		err = json.Unmarshal(kv.Value, &hosts[i])
		if err != nil {
			log.Debugf("ListHosts: Error %s", err)
			return nil, err
		}
	}
	return hosts, nil
}

func (kvStore KvStore) GetHost(hostID uint64) (common.Host, error) {
	host := common.Host{}
	key := kvStore.makeKey("hosts/%d", hostID)
	exists, err := kvStore.Db.Exists(key)
	if err != nil {
		log.Debugf("GetHost: Error %s", err)
		return host, err
	}
	if !exists {
		return host, common.NewError404("host", fmt.Sprintf("%d", hostID))
	}
	kvPair, err := kvStore.Db.Get(key)
	if err != nil {
		log.Debugf("GetHost: Error %s", err)
		return host, err
	}
	err = json.Unmarshal(kvPair.Value, &host)
	return host, err
}

func init() {
	// Register etcd store to libkv
	etcd.Register()
}
