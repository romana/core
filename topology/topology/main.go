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
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Command to launch topology service
package main

import (
	"flag"
	"fmt"

	"github.com/romana/core/common"
	"github.com/romana/core/topology"
)

// Main entry point for the topology microservice
func main() {
	createSchema := flag.Bool("createSchema", false, "Create schema")
	overwriteSchema := flag.Bool("overwriteSchema", false, "Overwrite schema")
	rootURL := flag.String("rootURL", "", "Root service URL")
	version := flag.Bool("version", false, "Build Information.")
	username := flag.String("username", "", "Username")
	password := flag.String("password", "", "Password")

	flag.Parse()

	if *version {
		fmt.Println(common.BuildInfo())
		return
	}
	if *rootURL == "" {
		fmt.Println("Must specify rootURL.")
		return
	}
	if *createSchema || *overwriteSchema {
		err := topology.CreateSchema(*rootURL, *overwriteSchema)
		if err != nil {
			panic(err)
		}
		fmt.Println("Schema created.")
		return
	}

	cred := common.MakeCredentialFromCliArgs(*username, *password)
	svcInfo, err := topology.Run(*rootURL, cred)
	if err != nil {
		panic(err)
	}

	for {
		msg := <-svcInfo.Channel
		fmt.Println(msg)
	}
}
