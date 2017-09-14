package policycontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/romana/core/agent/internal/cache/policycache"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"

	"github.com/docker/libkv/store"
	"github.com/pkg/errors"
)

func Run(ctx context.Context, key string, client *client.Client, storage policycache.Interface) (chan api.Policy, error) {
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
				respCh, err = client.Store.WatchExt(
					key,
					store.WatcherOptions{Recursive: true,
						NoList:     true,
						AfterIndex: LastIndex,
					},
					ctx.Done())
			}
			if err != nil {
				log.Printf("failed to reconnect policy watcher %s", err)
				time.Sleep(1)
				continue
			}

			select {
			case <-ctx.Done():
				return
			case resp, ok := <-respCh:
				if !ok {
					err = fmt.Errorf("channel closed")
				}

				LastIndex = resp.LastIndex
				var p api.Policy

				value := resp.Value
				if resp.Action == "delete" {
					value = resp.PrevValue
				}

				if errp := json.Unmarshal([]byte(value), &p); errp != nil {
					log.Printf("failed to unmarshal policy %v, err=%s", value, err)
					continue
				}

				updateStorage(resp.Action, resp.Key, p)
				policyOut <- p
			}

		}
	}()

	return policyOut, nil
}
