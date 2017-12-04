package policycontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/romana/core/agent/policycache"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"

	"github.com/docker/libkv/store"
	"github.com/pkg/errors"
	log "github.com/romana/rlog"
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
				log.Debugf("policy watcher store error: %s", err)
				respCh, err = client.Store.WatchExt(
					key,
					store.WatcherOptions{Recursive: true,
						NoList:     true,
						AfterIndex: LastIndex,
					},
					ctx.Done())
			}
			if err != nil {
				// if we can't connect to the kvstore, wait for
				// few seconds and try reconnecting.
				log.Printf("error while connecting to kvstore for policy watcher: %s",
					err)
				time.Sleep(5 * time.Second)
				continue
			}

			select {
			case <-ctx.Done():
				log.Printf("\nStopping policy watcher module.\n")
				return

			case resp, ok := <-respCh:
				if !ok {
					err = fmt.Errorf("kvstore policy events channel closed")
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
