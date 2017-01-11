// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package main

import (
	"flag"
	"fmt"
	"github.com/romana/core/common"
	"github.com/romana/core/pkg/util/policy/cache"
)

func main() {
	var rootURL = flag.String("rootURL", "", "URL to root service URL")
	flag.Parse()

	if *rootURL == "" {
		fmt.Println("Must specify rootURL.")
		return
	}

	clientConfig := common.GetDefaultRestClientConfig(*rootURL, nil)
	client, err := common.NewRestClient(clientConfig)
	if err != nil {
		fmt.Printf("Error %s", err)
		return
	}

	c := cache.New(client, cache.Config{CacheTickSeconds: 10})

	stop := make(chan struct{})
	update := c.Run(stop)

	for {
		select {
		case hash := <-update:
			fmt.Printf("New policy hash %s\n", hash)
			PrintPolicy(c)
		}
	}
}

func PrintPolicy(cache cache.Interface) {
	policies := cache.List()
	for policyNum, policy := range policies {
		fmt.Printf("Policy %d name %s\n", policyNum, policy.Name)
	}

	fmt.Printf("Detected %d romana policies\n", len(cache.List()))
}
