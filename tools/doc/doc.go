// Copyright (c) 2015 Pani Networks
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
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/romana/core/agent"
	"github.com/romana/core/common"
	"github.com/romana/core/ipam"
	"github.com/romana/core/policy"
	"github.com/romana/core/tools"
)

func main() {

	if len(os.Args) != 2 {
		log.Fatalf("%s <path>", os.Args[0])
	}
	path := os.Args[1]
	log.Printf("Analyzing %s", path)
	a := tools.NewAnalyzer(path)
	a.Analyze()

	// TODO this can be introspectable as well
	//	serviceInterfaceName := "github.com/romana/core/common.Service"
	//	implementors := a.FindImplementors(serviceInterfaceName)
	//	log.Printf("The following implement the %s interface: %+v", serviceInterfaceName, implementors)

	services := []common.Service{&ipam.IPAMSvc{}, &agent.Agent{}, &policy.PolicySvc{}}
	for _, service := range services {
		rd := tools.NewSwaggerer(a, service)
		json, err := rd.Process()
		if err != nil {
			panic(err)
		}
		serviceName := service.Name()
		dir := fmt.Sprintf("doc/%s", serviceName)
		err = os.MkdirAll(dir, os.ModeDir|os.ModePerm)
		if err != nil {
			panic(err)
		}
		fname := fmt.Sprintf("%s/%s.yaml", dir, serviceName)
		err = ioutil.WriteFile(fname, json, 0644)
		if err != nil {
			panic(err)
		}
		log.Printf("Wrote %s", fname)
	}
}
