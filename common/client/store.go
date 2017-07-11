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

package client

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/docker/libkv"
	libkvStore "github.com/docker/libkv/store"
	libkvEtcd "github.com/docker/libkv/store/etcd"
	"github.com/romana/core/common"
	"github.com/romana/core/common/log/trace"
	log "github.com/romana/rlog"
)

// Store is a structure storing information specific to KV-based
// implementation of Store.
type Store struct {
	prefix string
	libkvStore.Store
}

func NewStore(etcdEndpoints []string, prefix string) (*Store, error) {
	var err error

	myStore := &Store{prefix: prefix}

	myStore.Store, err = libkv.NewStore(
		libkvStore.ETCD,
		etcdEndpoints,
		&libkvStore.Config{},
	)
	if err != nil {
		return nil, err
	}

	return myStore, nil
}

// BEGIN WRAPPER METHODS

// For now, the wrapper methods (below) just ensure the specified
// prefix is added to all keys (and this is mostly so that tests can
// run concurrently). Perhaps other things can be added later.

func (s *Store) Exists(key string) (bool, error) {
	return s.Store.Exists(s.prefix + key)
}

func (s *Store) PutObject(key string, v interface{}) error {
	key = s.prefix + key
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	log.Tracef(trace.Inside, "Saving object under key %s: %s", key, string(b))
	return s.Store.Put(key, b, nil)
}

func (s *Store) Get(key string) (*libkvStore.KVPair, error) {
	return s.Store.Get(s.prefix + key)
}

func (s *Store) GetBool(key string, defaultValue bool) (bool, error) {
	kvp, err := s.Store.Get(s.prefix + key)
	if err != nil {
		if err == libkvStore.ErrKeyNotFound {
			return defaultValue, nil
		}
		return false, err
	}
	return common.ToBool(string(kvp.Value))
}

func (s *Store) ListObjects(key string, obj interface{}) ([]interface{}, error) {
	kvps, err := s.Store.List(s.prefix + key)
	if err != nil {
		return nil, err
	}
	retval := make([]interface{}, len(kvps))
	for i, kvp := range kvps {
		err = json.Unmarshal(kvp.Value, obj)
		if err != nil {
			return nil, err
		}
		retval[i] = obj
	}
	return retval, nil
}

func (s *Store) GetObject(key string, obj interface{}) error {
	kvp, err := s.Store.Get(s.prefix + key)
	if err != nil {
		if err == libkvStore.ErrKeyNotFound {
			return nil
		}
		return err
	}
	return json.Unmarshal(kvp.Value, obj)
}

func (s *Store) GetString(key string, defaultValue string) (string, error) {
	kvp, err := s.Store.Get(s.prefix + key)
	if err != nil {
		if err == libkvStore.ErrKeyNotFound {
			return defaultValue, nil
		}
		return "", err
	}
	return string(kvp.Value), nil
}

func (s *Store) GetInt(key string, defaultValue int) (int, error) {
	kvp, err := s.Store.Get(s.prefix + key)
	if err != nil {
		if err == libkvStore.ErrKeyNotFound {
			return defaultValue, nil
		}
		return 0, err
	}
	str := string(kvp.Value)
	val, err := strconv.ParseInt(str, 32, 10)
	return int(val), err
}

// Delete wrapes Delete operation, returning:
// - true if deletion succeede
// - false and no error if deletion failed because key was not found
// - false and error if another error occurred
func (s *Store) Delete(key string) (bool, error) {
	err := s.Store.Delete(s.prefix + key)
	if err == nil {
		return true, nil
	}
	if err == libkvStore.ErrKeyNotFound {
		return false, nil
	}
	return false, err
}

// END WRAPPER METHODS

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
