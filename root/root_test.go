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

package root

import (
	"fmt"
	"github.com/romana/core/common"
	//	"log"
	"os"
	"strings"
	"testing"
)

// Test hooks
func TestHooks(t *testing.T) {

	fmt.Println("Entering TestHooks")
	dir, _ := os.Getwd()
	fmt.Println("In", dir)

	yamlFileName := "../common/testdata/romana.hooks.yaml"
	svcInfo, err := Run(yamlFileName)
	if err != nil {
		fmt.Println(err.Error())

	}

	fmt.Println("Waiting for message")
	msg := <-svcInfo.Channel
	fmt.Println("Root service said:", msg)
	rootURL := fmt.Sprintf("http://%s", svcInfo.Address)
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
	if err != nil {
		t.Error(err)

	}

	result1 := make(map[string]interface{})
	err = client.Get("/config/ipam", &result1)
	if err != nil {
		t.Error(err)

	}
	fmt.Println("Received: ", result1)

	file, err := os.Open("/tmp/hook.txt")
	if err != nil {
		t.Error(err)
	}
	data := make([]byte, 1024)
	n, err := file.Read(data)
	if err != nil {
		t.Error(err)
	}
	str := strings.TrimSpace(string(data[0:n]))
	fmt.Printf("Hook output: [%s]", str)
	expect := "Hello, world and body= serviceName=ipam"
	if str != expect {
		t.Error(fmt.Sprintf("Expected %s, received %s", expect, str))
	}

	url := fmt.Sprintf("%s/config/ipam/port", rootURL)
	result2 := make(map[string]interface{})
	portMsg := common.PortUpdateMessage{Port: 12345}
	err = client.Post(url, portMsg, &result2)
	fmt.Printf("Got %v", err)
	if err == nil {
		t.Error("Expected error, got nothing")
		t.FailNow()
	}
	fmt.Println("Received: ", result2)

	file, err = os.Open("/tmp/hook_bad.txt")
	if err != nil {
		t.Error(err)
	}
	data = make([]byte, 1024)
	n, err = file.Read(data)
	if err != nil {
		t.Error(err)
	}
	str = strings.TrimSpace(string(data[0:n]))
	fmt.Printf("Hook output: [%s]", str)
	expect = "Good-bye, cruel world"
	if str != expect {
		t.Error(fmt.Sprintf("Expected %s, received %s", expect, str))
	}
}

// Test the service list.
func TestAuth(t *testing.T) {
	fmt.Println("Entering TestServiceList")
	dir, _ := os.Getwd()
	fmt.Println("In", dir)

	yamlFileName := "../common/testdata/romana.auth.yaml"
	configFile, err := common.MockConfig(yamlFileName)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	fmt.Printf("Calling Run(%s)", configFile)
	svcInfo, err := Run(configFile)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println("Waiting for message")
	msg := <-svcInfo.Channel
	fmt.Println("Root service said:", msg)
	addr := fmt.Sprintf("http://%s", svcInfo.Address)

	clientConfig := common.GetDefaultRestClientConfig(addr)
	clientConfig.Credential = &common.Credential{Type: common.CredentialUsernamePassword, Username: "admin", Password: "password"}
	client, err := common.NewRestClient(clientConfig)

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
	fmt.Printf("Service name: %s", svcName)

	if svcName != "root" {
		t.Errorf("Expected serviceName to be root, got %s", svcName)
	}
}

// Test the service list.
func TestServiceList(t *testing.T) {
	fmt.Println("Entering TestServiceList")
	dir, _ := os.Getwd()
	fmt.Println("In", dir)

	yamlFileName := "../common/testdata/romana.sample.yaml"
	configFile, err := common.MockConfig(yamlFileName)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	fmt.Printf("Calling Run(%s)", configFile)
	svcInfo, err := Run(configFile)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	fmt.Println("Waiting for message")
	msg := <-svcInfo.Channel
	fmt.Println("Root service said:", msg)

	_, err = common.ReadConfig("/tmp/romana.yaml")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	rootURL := fmt.Sprintf("http://%s", svcInfo.Address)
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
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
	fmt.Printf("Service name: %s", svcName)

	if svcName != "root" {
		t.Errorf("Expected serviceName to be root, got %s", svcName)
	}
}
