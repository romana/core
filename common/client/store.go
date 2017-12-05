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
	"bytes"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
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
	//	etcdCli *clientv3.Client
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

	// BEGIN EXPERIMENT...
	//	myStore.etcdCli, err := clientv3.New(clientv3.Config{
	//		Endpoints: etcdEndpoints,
	//	})
	//	if err != nil {
	//		return nil, err
	//	}
	// END EXPERIMENT

	// Test connection
	_, err = myStore.Exists("test")
	if err != nil {
		return nil, err
	}

	return myStore, nil
}

func normalize(key string) string {
	key2 := strings.TrimSpace(key)
	elts := strings.Split(key2, "/")
	normalizedElts := make([]string, 0)
	for _, elt := range elts {
		elt = strings.TrimSpace(elt)
		if elt == "" {
			continue
		}
		normalizedElts = append(normalizedElts, elt)
	}
	normalizedKey := strings.Join(normalizedElts, "/")
	normalizedKey = "/" + normalizedKey
	//	log.Tracef(trace.Inside, "Normalized key %s to %s", key, normalizedKey)
	return normalizedKey
}

// s.getKey normalizes key and prepends prefix to it
func (s *Store) getKey(key string) string {
	// See https://github.com/docker/libkv/blob/master/store/helpers.go#L15
	normalizedKey := normalize(s.prefix + "/" + key)
	return normalizedKey
}

// BEGIN WRAPPER METHODS

// For now, the wrapper methods (below) just ensure the specified
// prefix is added to all keys (and this is mostly so that tests can
// run concurrently). Perhaps other things can be added later.

func (s *Store) Exists(key string) (bool, error) {
	return s.Store.Exists(s.getKey(key))
}

func (s *Store) PutObject(key string, value []byte) error {
	key = s.getKey(key)
	log.Tracef(trace.Inside, "Saving object under key %s: %s", key, string(value))
	return s.Store.Put(key, value, nil)
}

// Atomizable defines an interface on which it is possible to execute
// Atomic operations from the point of view of KVStore.
type Atomizable interface {
	GetPrevKVPair() *libkvStore.KVPair
	SetPrevKVPair(*libkvStore.KVPair)
}

func (s *Store) AtomicPut(key string, value Atomizable) error {
	key = s.getKey(key)
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	prevVal := value.GetPrevKVPair()
	ok, kvp, err := s.Store.AtomicPut(key, b, prevVal, nil)
	if err != nil {
		return err
	}
	if !ok {
		return common.NewError("Could not store value under %s", key)
	}
	value.SetPrevKVPair(kvp)
	prevIdx := uint64(0)
	if prevVal != nil {
		prevIdx = prevVal.LastIndex
	}
	log.Tracef(trace.Inside, "%d: AtomicPut(): At key %s, went from %d to %d", getGID(), key, prevIdx, kvp.LastIndex)
	return nil
}

func (s *Store) Get(key string) (*libkvStore.KVPair, error) {
	return s.Store.Get(s.getKey(key))
}

func (s *Store) GetBool(key string, defaultValue bool) (bool, error) {
	kvp, err := s.Store.Get(s.getKey(key))
	if err != nil {
		if err == libkvStore.ErrKeyNotFound {
			return defaultValue, nil
		}
		return false, err
	}
	return common.ToBool(string(kvp.Value))
}

func (s *Store) ListObjects(key string) ([]*libkvStore.KVPair, error) {
	kvps, err := s.Store.List(s.getKey(key))
	if err != nil {
		return nil, err
	}
	return kvps, nil
}

func (s *Store) GetObject(key string) (*libkvStore.KVPair, error) {
	kvp, err := s.Store.Get(s.getKey(key))
	if err != nil {
		if err == libkvStore.ErrKeyNotFound {
			return nil, nil
		}
		return nil, err
	}
	return kvp, nil
}

func (s *Store) GetString(key string, defaultValue string) (string, error) {
	kvp, err := s.Store.Get(s.getKey(key))
	if err != nil {
		if err == libkvStore.ErrKeyNotFound {
			return defaultValue, nil
		}
		return "", err
	}
	return string(kvp.Value), nil
}

func (s *Store) GetInt(key string, defaultValue int) (int, error) {
	kvp, err := s.Store.Get(s.getKey(key))
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
	err := s.Store.Delete(s.getKey(key))
	if err == nil {
		return true, nil
	}
	if err == libkvStore.ErrKeyNotFound {
		return false, nil
	}
	return false, err
}

// END WRAPPER METHODS

// ReconnectingWatch wraps libkv Watch method, but attempts to re-establish
// the watch if it drop.
func (s *Store) ReconnectingWatch(key string, stopCh <-chan struct{}) (<-chan *libkvStore.KVPair, error) {
	outCh := make(chan *libkvStore.KVPair)
	inCh, err := s.Watch(s.getKey(key), stopCh)
	if err != nil {
		return nil, err
	}
	go s.reconnectingWatcher(key, stopCh, inCh, outCh)
	return outCh, nil
}

func (s *Store) reconnectingWatcher(key string, stopCh <-chan struct{}, inCh <-chan *libkvStore.KVPair, outCh chan *libkvStore.KVPair) {
	var err error
	log.Tracef(trace.Private, "Entering ReconnectingWatch goroutine: %d", getGID())
	channelClosed := false
	retryDelay := 1 * time.Millisecond
	for {
		select {
		case <-stopCh:
			log.Info("Stop message received for WatchHosts")
			return
		case kv, ok := <-inCh:
			if ok {
				channelClosed = false
				outCh <- kv
				break
			}
			// Not ok - channel continues to be closed

			if channelClosed {
				// We got here because we attempted to re-create
				// a watch but it came back with a closed channel again.
				// So we should increase the retry
				retryDelay *= 2
			} else {
				channelClosed = true
				retryDelay = 1 * time.Millisecond
			}
			log.Infof("ReconnectingWatch: Lost watch on %s, trying to re-establish...", key)
			for {
				inCh, err = s.Watch(s.getKey(key), stopCh)
				if err == nil {
					break
				} else {
					log.Errorf("ReconnectingWatch: Error reconnecting: %v (%T)", err, err)
					retryDelay *= 2
				}
			}
		}
	}
}

// Locker implements an interface for locking and unlocking.
// sync.Locker was not good for our purpose it does not allow
// for returning an error on lock. libkv's Locker is too libkv-specific
// and we do not need a stop channel really; and since the use case
// is to defer Unlock(), no need for it to return an error
type Locker interface {
	Lock() (<-chan struct{}, error)
	Unlock()
	GetOwner() uint64
}

// storeLocker implements Locker interface using the
// lock form the backend store.
type storeLocker struct {
	key   string
	owner uint64
	libkvStore.Locker
}

// See https://blog.sgmansfield.com/2015/12/goroutine-ids/
func getGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func (sl *storeLocker) GetOwner() uint64 {
	return sl.owner
}

// Lock implements Lock method of Locker interface.
func (sl *storeLocker) Lock() (<-chan struct{}, error) {
	stopChan := make(chan struct{})
	ch, err := sl.Locker.Lock(stopChan)
	if err == nil {
		sl.owner = getGID()
	} else {
		log.Tracef(trace.Inside, "%d: Error getting lock for %s: %s", getGID(), sl.key, err)
	}
	return ch, err
}

// Unlock implements Unlock method of Locker interface.
func (sl *storeLocker) Unlock() {
	prevOwner := sl.owner
	sl.owner = 0
	err := sl.Locker.Unlock()
	if err != nil {
		sl.owner = prevOwner
		//		switch err := err.(type) {
		//		case etcd.Error:
		//			if err.Code == etcd.ErrorCodeKeyNotFound {
		//				// If key is not found, then we did not hold the lock to begin with,
		//				// and unlock was called by a defer...
		//			}
		//		default:
		//			log.Errorf("%d: Error unlocking %s: %s (%T)", sl.key, err, err)
		//		}
		log.Errorf("%d: Error unlocking %s: %s (%T)", getGID(), sl.key, err, err)
	}
}

func (store *Store) NewLocker(name string) (Locker, error) {
	key := store.getKey("/lock/" + name)
	l, err := store.Store.NewLock(key, nil)
	if err != nil {
		return nil, err
	}
	return &storeLocker{key: key, Locker: l}, nil
}

// mutexLocker implements Locker interface with a sync.Mutex
type mutexLocker struct {
	mutex *sync.Mutex
	owner uint64
}

func (ml *mutexLocker) GetOwner() uint64 {
	return ml.owner
}

// Lock implements Lock method of Locker interface.
func (ml *mutexLocker) Lock() (<-chan struct{}, error) {
	ch := make(<-chan struct{})
	if ml.mutex == nil {
		ml.mutex = &sync.Mutex{}
	}
	ml.mutex.Lock()
	ml.owner = getGID()
	return ch, nil
}

// Unlock implements Unlock method of Locker interface.
func (ml *mutexLocker) Unlock() {
	ml.owner = 0
	ml.mutex.Unlock()
}

func newMutexLocker() *mutexLocker {
	return &mutexLocker{mutex: &sync.Mutex{}}
}

func init() {
	// Register etcd store to libkv
	libkvEtcd.Register()
}
