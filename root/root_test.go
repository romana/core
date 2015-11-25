// Copyright (c) 2015 Pani Networks
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

package root

import (
	"fmt"
	"github.com/romana/core/common"
	"os"
	"testing"
)

// Test the service list.
func TestServiceList(t *testing.T) {
	fmt.Println("Entering TestServiceList")
	dir, _ := os.Getwd()
	fmt.Println("In", dir)

	yamlFileName := "../common/testdata/pani.sample.yaml"
	fmt.Println("Calling Run()")
	channel, err := Run(yamlFileName)
	if err != nil {
		t.Error(err)
	}
	msg := <-channel
	fmt.Println("Root service said:", msg)
	addr := "http://localhost:9600"
	client , err := common.NewRestClient(addr)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	r := common.IndexResponse{}
	err = client.Get("", &r)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	fmt.Println("Received: ", r)
	svcName := r.ServiceName
	fmt.Println("Service name:", svcName)

	if svcName != "root" {
		t.Errorf("Expected serviceName to be root, got %s", svcName)
	}
}
