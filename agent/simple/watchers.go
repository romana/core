package main

import (
	"context"
	"time"

	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
)

// RomanaClientAdaptor allows using Romana client as RomanaClient interface.
// TODO this should go away when ListHosts and ListBlocks will be exposed
// on one struct, either client ot IPAM.
type RomanaClientAdaptor struct {
	*client.Client
}

func (c RomanaClientAdaptor) ListHosts() api.HostList {
	return c.ListHosts()
}

func (c RomanaClientAdaptor) ListAllBlocks() *api.IPAMBlocksResponse {
	return c.IPAM.ListAllBlocks()
}

// RomanaClient exists for a purpose of mocking.
type RomanaClient interface {
	ListHosts() api.HostList
	ListAllBlocks() *api.IPAMBlocksResponse
}

const watchersRefreshTimer = time.Duration(10 * time.Second)

// WatchBlocks is a generator that should produce a list of all blocks when change is detected in
// blocks configuration.
func WatchBlocks(ctx context.Context, client RomanaClient) <-chan []api.IPAMBlockResponse {
	out := make(chan []api.IPAMBlockResponse)
	ticker := time.Tick(watchersRefreshTimer)

	var blocks []api.IPAMBlockResponse

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker:
				blockResp := client.ListAllBlocks()
				if blockResp != nil {
					blocks = blockResp.Blocks
				} else {
					blocks = []api.IPAMBlockResponse{}
				}

				out <- blocks
			}

		}
	}()

	return out
}

// WatchHosts is a generator that should produce a list of all hosts when change is detected in
// hosts configuration.
func WatchHosts(ctx context.Context, client RomanaClient) <-chan []api.Host {
	out := make(chan []api.Host)
	ticker := time.Tick(watchersRefreshTimer)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker:
				out <- client.ListHosts().Hosts
			}

		}
	}()

	return out
}
