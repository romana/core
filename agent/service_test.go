// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
package agent

// Some comments on use of mocking framework in helpers_test.go.

import (
	"fmt"
	"github.com/romana/core/common"
	"log"
	"os"
	"testing"
)

func startAgent(t *testing.T) {
	cwd, err := os.Getwd()
	fmt.Println("In", cwd)
	if err != nil {
		panic(err)
	}
	rootURL := fmt.Sprintf("file://%s/testdata/root.json", cwd)
	svcInfo, err := Run(rootURL, true)
	if err != nil {
		t.Fatal(err)
	}
	msg := <-svcInfo.Channel
	t.Log("Service says", msg)
	fmt.Println(msg)
}

// TestK8SHandler will test K8S handler
func TestK8SHandler(t *testing.T) {
	startAgent(t)
	restClient := common.RestClient{}
	options := make(map[string]string)
	options[fullIsolationOption] = "on"
	nr := NetworkRequest{NetIf{}, options}
	result := make(map[string]string)
	restClient.Post("http://localhost:8899", nr, &result)
	log.Printf("Sent to agent %v, agent returned %v", nr, result)

}
