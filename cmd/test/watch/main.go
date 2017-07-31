package main

import (
	"flag"
	"strings"
	"sync"

	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"
	log "github.com/romana/rlog"
)

func main() {
	endpointsStr := flag.String("etcd-endpoints", client.DefaultEtcdEndpoints, "Comma-separated list of etcd endpoints.")
	flag.Parse()
	endpoints := strings.Split(*endpointsStr, ",")
	config := common.Config{EtcdEndpoints: endpoints}
	client, err := client.NewClient(&config)
	if err != nil {
		panic(err)
	}

	log.Infof("WatchTest: Starting WatchHostsWithCallback")
	client.WatchHostsWithCallback(func(h api.HostList) {
		log.Infof("WatchTest (Callback): Received new host list of length %d, revision %d", len(h.Hosts), h.Revision)
	})

	log.Infof("WatchTest: Starting WatchBlocksWithCallback")
	client.WatchBlocksWithCallback(func(b api.IPAMBlocksResponse) {
		log.Infof("WatchTest (Callback): Received new block list of length %d, revision %d", len(b.Blocks), b.Revision)
	})

	var wg sync.WaitGroup
	wg.Add(2)

	stopCh := make(chan struct{})
	blockCh, err := client.WatchBlocks(stopCh)
	if err != nil {
		panic(err)
	}
	log.Infof("WatchTest: Starting Blocks Watcher")
	go func() {
		defer wg.Done()
		for {
			select {
			case b, ok := <-blockCh:
				if ok {
					log.Infof("WatchTest (Channel): Received new block list of length %d, revision %d", len(b.Blocks), b.Revision)
				} else {
					log.Infof("WatchTest: Block watch lost.")
					return
				}
			}
		}
	}()

	stopCh = make(chan struct{})
	hostCh, err := client.WatchHosts(stopCh)
	if err != nil {
		panic(err)
	}
	log.Infof("WatchTest: Starting Host Watcher")
	go func() {
		defer wg.Done()
		for {
			select {
			case h, ok := <-hostCh:
				if ok {
					log.Infof("WatchTest (Channel): Received new host list of length %d, revision %d", len(h.Hosts), h.Revision)
				} else {
					log.Infof("WatchTest: Host watch lost.")
					return
				}
			}
		}
	}()

	wg.Wait()
}
