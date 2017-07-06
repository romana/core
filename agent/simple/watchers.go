package main

import (
	"context"
	"time"

	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
)

const watchersRefreshTimer = time.Duration(10 * time.Second)

// WatchBlocks is a generator that should produce a list of all blocks when change is detected in
// blocks configuration.
func WatchBlocks(ctx context.Context, client *client.Client) <-chan []api.IPAMBlockResponse {
	out := make(chan []api.IPAMBlockResponse)
	ticker := time.Tick(watchersRefreshTimer)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker:
				out <- client.IPAM.ListAllBlocks()
			}

		}
	}()

	return out
}

// WatchHosts is a generator that should produce a list of all hosts when change is detected in
// hosts configuration.
func WatchHosts(ctx context.Context, client *client.Client) <-chan []api.Host {
	out := make(chan []api.Host)
	ticker := time.Tick(watchersRefreshTimer)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker:
				out <- client.ListHosts()
			}

		}
	}()

	return out
}
