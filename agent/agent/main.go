// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Command for running the agent.

package main

import (
	"flag"
	"fmt"
	"github.com/romana/core/agent"
)

// Build Information and Timestamp.
// Pass build information to the executable using go run as below:
//
// go run  -ldflags "-X main.buildInfo=`git describe --always`" \
// -X main.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` main.go \
// -version
//
// or using go build as below:
//
// go build -ldflags "-X main.buildInfo=`git describe --always` \
// -X main.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'`" main.go
//
var buildInfo = "No Build Information Provided"
var buildTimeStamp = "No Build Time Provided"

// main function is entrypoint to everything.
func main() {
	var rootURL = flag.String("rootUrl", "", "URL to root service URL")
	var version = flag.Bool("version", false, "Build Information.")
	flag.Parse()

	if *version {
		fmt.Println("Build Revision: ", buildInfo)
		fmt.Println("Build Time: ", buildTimeStamp)
	}
	if rootURL == nil {
		fmt.Println("Must specify rootUrl.")
		return
	}
	channel, _, err := agent.Run(*rootURL)
	if err != nil {
		panic(err)
	}
	for {
		msg := <-channel
		fmt.Println(msg)
	}
}
