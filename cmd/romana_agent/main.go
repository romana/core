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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/romana/core/agent"
	"github.com/romana/core/agent/cache/policycache"
	"github.com/romana/core/agent/enforcer"
	utilexec "github.com/romana/core/agent/exec"
	"github.com/romana/core/agent/policycontroller"
	"github.com/romana/core/agent/rtable"
	"github.com/romana/core/agent/sysctl"
	"github.com/romana/core/common"
	"github.com/romana/core/common/api"
	"github.com/romana/core/common/client"

	log "github.com/romana/rlog"
	"github.com/vishvananda/netlink"
)

const (
	DefaultRouteTableId = 10
	DefaultGwIP         = "172.142.0.1"
)

var (
	kernelParameter = []string{
		"/proc/sys/net/ipv4/conf/default/proxy_arp",
		"/proc/sys/net/ipv4/conf/all/proxy_arp",
		"/proc/sys/net/ipv4/ip_forward",
	}
)

func main() {
	var err error

	etcdEndpoints := flag.String("endpoints", "", "csv list of etcd endpoints to romana storage")
	etcdPrefix := flag.String("prefix", "", "string that prefixes all romana keys in etcd")
	hostname := flag.String("hostname", "", "name of the host in romana database")
	provisionIface := flag.Bool("provision-iface", false, "create romana-gw interface and ip")
	provisionIfaceGwIp := flag.String("provision-iface-gw-ip", DefaultGwIP, "specifies ip address for gateway interface")
	provisionSysctls := flag.Bool("provision-sysctls", false, "configure routing sysctls")
	romanaRouteTableId := flag.Int("route-table-id", DefaultRouteTableId,
		"id that romana route table should have in /etc/iproute2/rt_tables")
	multihop := flag.Bool("multihop-blocks", false, "allows multihop blocks")
	policyEnforcer := flag.Bool("policy", false, "enable romana policies")
	flag.Parse()

	fmt.Println(common.BuildInfo())

	romanaConfig := common.Config{
		EtcdEndpoints: strings.Split(*etcdEndpoints, ","),
		EtcdPrefix:    *etcdPrefix,
	}

	if *hostname == "" {
		*hostname, err = os.Hostname()
		if err != nil {
			panic(err)
		}
	}

	romanaClient, err := client.NewClient(&romanaConfig)
	if err != nil {
		log.Errorf("Failed to initialize romana client: %v", err)
		os.Exit(2)
	}

	if *provisionIface {
		err := agent.CreateRomanaGW()
		if err != nil {
			log.Errorf("Failed to create romana-gw interface. %s", err)
			os.Exit(2)
		}

		err = agent.SetRomanaGwIP(*provisionIfaceGwIp)
		if err != nil {
			log.Errorf("Failed to install ip address on romana-gw interface. %s", err)
			os.Exit(2)
		}

	}

	if *provisionSysctls {
		err := setSysctls()
		if err != nil {
			log.Errorf("Failed to set sysctls %s", err)
			os.Exit(2)
		}
	}

	ok, err := checkSysctls()
	if err != nil {
		log.Errorf("Failed verify the state of essential systls %s", err)
		os.Exit(2)
	}
	if !ok {
		log.Errorf("Essential sysctls not set, consider using -provision-sysctls flag and ensure you are running from root")
		os.Exit(2)
	}

	err = rtable.EnsureRouteTableExist(*romanaRouteTableId)
	if err != nil {
		log.Errorf("Failed to make `romana` alias for route table=%d, %s. Unable to continue", *romanaRouteTableId, err)
		os.Exit(2)
	}

	nlHandle, err := netlink.NewHandle()
	if err != nil {
		log.Errorf("Failed to create netlink handle %s", err)
		os.Exit(2)
	}
	defer nlHandle.Delete()

	err = rtable.EnsureRomanaRouteRule(*romanaRouteTableId, nlHandle)
	if err != nil {
		log.Errorf("Failed to install route rule for romana routing table, %s", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	blocksChannel, err := romanaClient.WatchBlocks(ctx.Done())
	if err != nil {
		log.Errorf("Failed to subscribe to Romana blocks updates, %s", err)
		os.Exit(2)
	}

	if *policyEnforcer {
		ctx := context.Background()
		policyCache := policycache.New()
		var policyEtcdKey = "/romana/policies"
		policies, err := policycontroller.Run(ctx, policyEtcdKey, romanaClient, policyCache)
		if err != nil {
			log.Errorf("Failed to start policy controller, %s", err)
			os.Exit(2)
		}

		blocksList := romanaClient.IPAM.ListAllBlocks()

		// blocks are needed in both, route agent and policy agent
		// this duplicates blocks channel into the 2 new channels, one
		// used here for policies and another one passed down for routes.
		var extraBlocksChannel <-chan api.IPAMBlocksResponse
		blocksChannel, extraBlocksChannel = fanOut(ctx, blocksChannel)

		enforcer, err := enforcer.New(policyCache, policies, *blocksList, extraBlocksChannel, *hostname, new(utilexec.DefaultExecutor), 10)
		if err != nil {
			log.Errorf("Failed to create policy enforcer, %s", err)
			os.Exit(2)
		}

		enforcer.Run(ctx)

	}

	hostsChannel, err := romanaClient.WatchHosts(ctx.Done())
	if err != nil {
		log.Errorf("Failed to start watching for blocks, %s", err)
		os.Exit(2)
	}

	hosts := agent.IpamHosts{}
	for {
		select {
		case blocks := <-blocksChannel:
			startTime := time.Now()
			err := rtable.FlushRomanaTable()
			if err != nil {
				log.Errorf("failed to flush romana route table err=(%s)", err)
				continue
			}

			agent.CreateRouteToBlocks(blocks.Blocks, hosts, *romanaRouteTableId, *hostname, *multihop, nlHandle)
			runTime := time.Now().Sub(startTime)
			log.Tracef(4, "Time between route table flush and route table rebuild %s", runTime)

		case newHosts := <-hostsChannel:
			// TODO need mutex for this.
			hosts = agent.IpamHosts(newHosts.Hosts)
		}
	}
}

// fanOut duplicates data from one channel into 2 identical channels.
func fanOut(ctx context.Context, in <-chan api.IPAMBlocksResponse) (<-chan api.IPAMBlocksResponse, <-chan api.IPAMBlocksResponse) {
	out1 := make(chan api.IPAMBlocksResponse, 1)
	out2 := make(chan api.IPAMBlocksResponse, 1)

	go func() {
		for {
			select {
			case b := <-in:
				log.Trace(5, "Blocks fan out tick")
				out1 <- b
				out2 <- b
			case <-ctx.Done():
				close(out1)
				close(out2)
				return
			}

		}

	}()

	return out1, out2
}

// checkSysctls checks that esseantial sysctl options are set.
func checkSysctls() (ok bool, err error) {
	for _, path := range kernelParameter {
		ok, err = sysctl.Check(path)
		if !ok || err != nil {
			break
		}
	}

	return ok, err
}

// setSysctls sets essential sysctl options.
func setSysctls() (err error) {
	for _, path := range kernelParameter {
		err = sysctl.Set(path)
		if err != nil {
			break
		}
	}
	return err
}
