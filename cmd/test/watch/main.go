package main

import (
	"flag"
	"strings"
	"sync"

	"github.com/romana/core/common"
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

	var wg sync.WaitGroup
	wg.Add(2)
	stopCh := make(chan struct{})
	hostCh, err := client.WatchHosts(stopCh)
	if err != nil {
		panic(err)
	}
	go func() {
		defer wg.Done()
		for {
			select {
			case h, ok := <-hostCh:
				if ok {
					log.Infof("Received new host list of length %d, revision %d", len(h.Hosts), h.Revision)
				} else {
					log.Infof("Host watch lost.")
					return
				}
			}
		}
	}()

	blockCh, err := client.WatchBlocks(stopCh)
	if err != nil {
		panic(err)
	}
	go func() {
		defer wg.Done()
		for {
			select {
			case b, ok := <-blockCh:
				if ok {
					log.Infof("Received new block list of length %d, revision %d", len(b.Blocks), b.Revision)
				} else {
					log.Infof("Block watch lost.")
					return
				}
			}
		}
	}()

	wg.Wait()
}
