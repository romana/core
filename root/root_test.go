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

// Test
package root

import (
	"fmt"
	"github.com/romanaproject/pani_core/common"
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
	msg := <- channel
	fmt.Println("Root service said:", msg)
	addr := "http://localhost:8000"
	client := common.RestClient{addr}
	
	data, err := client.HttpGet("/")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(data)
}
