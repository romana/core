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

package common

import (
	"sync"
	"time"

	"github.com/docker/libkv"
	libkvStore "github.com/docker/libkv/store"
	libkvEtcd "github.com/docker/libkv/store/etcd"
	log "github.com/romana/rlog"
)

// StoreConfig stores information needed for a connection to backing store.
// It is just a typed collection of all possible required parameters, a
// superset of them.
type StoreConfig struct {
	Endpoints []string
	Prefix    string
}

// Store is a structure storing information specific to KV-based
// implementation of Store.
type Store struct {
	Config StoreConfig
	libkvStore.Store
}

func (s *Store) Exists(key string) (bool, error) {
	return s.Store.Exists(s.Config.Prefix + key)
}

func (s *Store) Put(key string, val []byte) error {
	return s.Store.Put(s.Config.Prefix + key, val, nil )
}


(ipamDataKey, b, nil)

func (s *Store) Get(key string) (*libkvStore.KVPair, error) {
	return s.Store.Get(s.Config.Prefix + key)
}

func NewStore(config StoreConfig) (*Store, error) {
	var err error

	myStore := &Store{Config: config}

	myStore.Store, err = libkv.NewStore(
		libkvStore.ETCD,
		config.Endpoints,
		&libkvStore.Config{},
	)
	if err != nil {
		return nil, err
	}

	return myStore, nil
}

// StoreLocker implements sync.Locker interface using the
// lock form the backend store.
type storeLocker struct {
	key string
	libkvStore.Locker
}

func (store *Store) NewLocker(name string) (sync.Locker, error) {
	key := "/romana/lock/" + name
	l, err := store.Store.NewLock(key, nil)
	if err != nil {
		return nil, err
	}
	return &storeLocker{key: key, Locker: l}, nil
}

// Lock implements Lock method of sync.Locker interface.
// TODO this can block forever -- but there is nothing to
// do when we fail to lock other than not proceed in the caller,
// so while retries can be implemented later, that's about it.
func (sl *storeLocker) Lock() {
	// TODO do we need these channels?
	stopChan := make(chan struct{})
	var err error
	for {
		_, err = sl.Locker.Lock(stopChan)
		if err == nil {
			return
		}
		log.Errorf("Error attempting to acquire lock for %s: %s", sl.key, err)
		time.Sleep(100 * time.Millisecond)
	}
}

// Unlock implements Unlock method of sync.Locker interface.
func (sl *storeLocker) Unlock() {
	err := sl.Locker.Unlock()
	if err != nil {
		// There is nothing, really, to do if we get an error,
		// and if not handled here, all this would do is not allow callers to defer.
		log.Errorf("Error unlocking %s: %s", sl.key, err)
	}
}

func init() {
	// Register etcd store to libkv
	libkvEtcd.Register()
}
