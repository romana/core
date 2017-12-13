// Copyright (c) 2017 Pani Networks
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

package policycontroller

import (
	"context"
	"encoding/json"
	"time"

	"github.com/romana/core/agent/policycache"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"

	"github.com/docker/libkv/store"
	"github.com/pkg/errors"
	log "github.com/romana/rlog"
)

const (
	defaultWatcherReconnectTime = 5 * time.Second
)

func Run(ctx context.Context, key string, client *client.Client, storage policycache.Interface) (<-chan api.Policy, error) {
	policies, err := client.Store.GetExt(key, store.GetOptions{Recursive: true})
	if err != nil {
		return nil, errors.Wrap(err, "controller init fail")
	}

	for _, val := range policies.GetResponse().Node.Nodes {
		var policy api.Policy
		err := json.Unmarshal([]byte(val.Value), &policy)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal policy")
		}

		storage.Put(val.Key, policy)
	}

	respCh, err := client.Store.WatchExt(
		key, store.WatcherOptions{Recursive: true, NoList: true}, ctx.Done())
	if err != nil {
		return nil, errors.Wrap(err, "failed to start watching")
	}

	updateStorage := func(action, key string, policy api.Policy) {
		switch action {
		case "set", "update", "create", "compareAndSwap":
			storage.Put(key, policy)
		case "delete":
			storage.Delete(key)
		}
	}

	policyOut := make(chan api.Policy)
	var LastIndex uint64
	go func() {
		var err error
		for {
			if err != nil {
				log.Errorf("policy watcher store error: %s", err)
				// if we can't connect to the kvstore, wait for
				// few seconds and try reconnecting.
				time.Sleep(defaultWatcherReconnectTime)
				respCh, _ = client.Store.WatchExt(
					key,
					store.WatcherOptions{Recursive: true,
						NoList:     true,
						AfterIndex: LastIndex,
					},
					ctx.Done())
			}

			select {
			case <-ctx.Done():
				log.Printf("Stopping policy watcher module.")
				return

			case resp, ok := <-respCh:
				if !ok || resp == nil {
					err = errors.New("kvstore policy events channel closed")
					continue
				}

				LastIndex = resp.LastIndex
				var p api.Policy

				value := resp.Value
				if resp.Action == "delete" {
					value = resp.PrevValue
				}

				if errp := json.Unmarshal([]byte(value), &p); errp != nil {
					log.Printf("failed to unmarshal policy %v, err=%s", value, errp)
					continue
				}

				updateStorage(resp.Action, resp.Key, p)
				policyOut <- p
			}

		}
	}()

	return policyOut, nil
}
