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
	"encoding/json"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"

	"net/url"

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

// Currently unimplemented
func (kvStore *KvStore) Find(query url.Values, entities interface{}, flag common.FindFlag) (interface{}, error) {
	return nil, nil
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
	lockKey := fmt.Sprintf("%s/lock", key)
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
		idRingKey := fmt.Sprintf("%s/ids", key)
		idRingKvPair, err := kvStore.Db.Get(idRingKey)
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
		err = kvStore.Db.Put(idRingKey, idRingBytes, nil)
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
	var id uint64
	lockKey := fmt.Sprintf("%s/lock", key)
	lock, err := kvStore.Db.NewLock(lockKey, nil)
	if err != nil {
		return 0, err
	}
	stopChan := make(chan struct{})
	ch, err := lock.Lock(stopChan)
	if err != nil {
		return 0, err
	}
	defer lock.Unlock()

	select {
	default:
		idRingKey := fmt.Sprintf("%s/ids", key)
		idRingKvPair, err := kvStore.Db.Get(idRingKey)
		if err != nil {
			return 0, err
		}
		idRing, err := common.DecodeIDRing(idRingKvPair.Value)
		if err != nil {
			return 0, err
		}
		id, err = idRing.GetID()
		if err != nil {
			return 0, err
		}
		idRingBytes, err := idRing.Encode()
		if err != nil {
			return 0, err
		}
		err = kvStore.Db.Put(idRingKey, idRingBytes, nil)
		if err != nil {
			return 0, err
		}
		return id, nil
	case <-ch:
		return id, nil
	}
}

// CreateSchema creates the schema in this DB. If force flag
// is specified, the schema is dropped and recreated.
func (kvStore *KvStore) CreateSchema(force bool) error {
	err := kvStore.Connect()
	if err != nil {
		return err
	}
	toInit := []string{"hosts/ids", "tenant/ids", "segment/ids"}
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
	return key
}

func (kvStore *KvStore) AddHost(dc common.Datacenter, host *common.Host) error {
	var err error
	hostsKey := kvStore.makeKey("network/hosts/ids")
	if host.ID == 0 {
		host.ID, err = kvStore.getID(hostsKey)
		log.Debugf("AddHost: Made ID %d", host.ID)
		if err != nil {
			log.Debugf("AddHost: Error getting new ID: %s", err)
			return err
		}
	}

	romanaIP := strings.TrimSpace(host.RomanaIp)
	if romanaIP == "" {
		host.RomanaIp, err = getNetworkFromID(host.ID, dc.PortBits, dc.Cidr)
		if err != nil {
			log.Debugf("AddHost: Error in getNetworkFromID: %s", err)
			return err
		}
	}
	key := kvStore.makeKey("network/hosts/%d", host.ID)
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

	key := kvStore.makeKey("network/hosts/%d", hostID)
	err := kvStore.Db.Delete(key)
	if err != nil {
		log.Debugf("DeleteHost: Error %s", err)
		return err
	}
	hostsKey := kvStore.makeKey("network/hosts/ids")
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
	key := kvStore.makeKey("network/hosts/")
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
	key := kvStore.makeKey("network/hosts/%d", hostID)
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
