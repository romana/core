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

// Command for running the agent.

package main

import (
	"flag"
	"fmt"
	"github.com/romana/core/agent"
	"github.com/romana/core/common"
)

// main function is entrypoint to everything.
func main() {
	var rootURL = flag.String("rootURL", "", "URL to root service URL")
	var version = flag.Bool("version", false, "Build Information.")
	flag.Parse()

	if *version {
		fmt.Println(common.BuildInfo())
		return
	}
	if rootURL == nil {
		fmt.Println("Must specify rootURL.")
		return
	}
	svcInfo, err := agent.Run(*rootURL, false)
	if err != nil {
		panic(err)
	}
	for {
		msg := <-svcInfo.Channel
		fmt.Println(msg)
	}
}
