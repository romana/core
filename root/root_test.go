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

package root

import (
	"fmt"
	"github.com/go-check/check"
	"github.com/romana/core/common"
	"github.com/romana/core/tenant"
	"net/http"
	"os"
	"strings"
	"testing"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MySuite struct {
	common.RomanaTestSuite
	rootURL string
}

var _ = check.Suite(&MySuite{})

func (s *MySuite) TestHooks(c *check.C) {

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
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL, nil))
	if err != nil {
		c.Fatal(err)
	}

	result1 := make(map[string]interface{})
	err = client.Get("/config/ipam", &result1)
	if err != nil {
		c.Fatal(err)
	}
	fmt.Println("Received: ", result1)

	file, err := os.Open("/tmp/hook.txt")
	if err != nil {
		c.Fatal(err)
	}
	data := make([]byte, 1024)
	n, err := file.Read(data)
	if err != nil {
		c.Fatal(err)
	}
	str := strings.TrimSpace(string(data[0:n]))
	fmt.Printf("Hook output: [%s]", str)
	expect := "Hello, world and body= serviceName=ipam"
	if str != expect {
		c.Fatalf("Expected %s, received %s", expect, str)
	}

	url := fmt.Sprintf("%s/config/ipam/port", rootURL)
	result2 := make(map[string]interface{})
	portMsg := common.PortUpdateMessage{Port: 12345}
	err = client.Post(url, portMsg, &result2)
	fmt.Printf("Got %v", err)
	if err == nil {
		c.Fatal("Expected error, got nothing")

	}
	fmt.Println("Received: ", result2)

	file, err = os.Open("/tmp/hook_bad.txt")
	if err != nil {
		c.Fatal(err)
	}
	data = make([]byte, 1024)
	n, err = file.Read(data)
	if err != nil {
		c.Fatal(err)
	}
	str = strings.TrimSpace(string(data[0:n]))
	fmt.Printf("Hook output: [%s]", str)
	expect = "Good-bye, cruel world"
	if str != expect {
		c.Fatalf("Expected %s, received %s", expect, str)
	}
}

// expect403 fails if the error is not a common.HttpError
// with a status code of 403.
func expect403(c *check.C, err error) {
	common.ExpectHttpError(c, err, http.StatusForbidden)
}

// getClientForAuthTest is a convenience method to get a client
// with the appropriate credentials for TestAuth method.
// If username is an empty string, a nil credential is assumed.
func (s *MySuite) getClientForTestAuth(c *check.C, username string, password string) (*common.RestClient, error) {
	var cred *common.Credential
	if username == "" {
		cred = nil
	} else {
		cred = &common.Credential{
			Type:     common.CredentialUsernamePassword,
			Username: username,
			Password: password,
		}
	}
	return common.NewRestClient(common.GetDefaultRestClientConfig(s.rootURL, cred))
}

// Test Auth functionality
func (s *MySuite) TestAuth(c *check.C) {
	dir, _ := os.Getwd()
	fmt.Println("In", dir)
	err := s.RomanaTestSuite.MockConfig("../common/testdata/romana.auth.yaml")
	if err != nil {
		c.Fatal(err)
	}
	fmt.Printf("Calling Run(%s)", s.RomanaTestSuite.ConfigFile)

	err = CreateSchema(s.RomanaTestSuite.ConfigFile, true)
	if err != nil {
		c.Fatal(err)
	}

	svcInfo, err := Run(s.RomanaTestSuite.ConfigFile)
	if err != nil {
		c.Fatal(err)
	}

	fmt.Println("Waiting for message")
	msg := <-svcInfo.Channel
	fmt.Println("Root service said:", msg)
	s.rootURL = fmt.Sprintf("http://%s", svcInfo.Address)

	// 1. Client with no credentials.
	noAuthClient, err := s.getClientForTestAuth(c, "", "")
	if err != nil {
		c.Fatal(err)
	}

	// Should not be allowed to get a configuration of a service
	_, err = noAuthClient.GetServiceConfig("ipam")
	expect403(c, err)

	// Getting root's index is fine
	r := common.IndexResponse{}
	err = noAuthClient.Get("/", &r)
	if err != nil {
		c.Fatal(err)
	}
	fmt.Println("Received: ", r)
	svcName := r.ServiceName
	fmt.Printf("Service name: %s", svcName)

	if svcName != common.ServiceNameRoot {
		c.Fatalf("Expected serviceName to be %s, got %s", common.ServiceNameRoot, svcName)
	}

	// 2. Client with wrong password in credential.
	// Let's try wrong pass client. This will result in an error but still
	// create a client - which is unauthenticated.
	wrongPassClient, err := s.getClientForTestAuth(c, "admin", "shmadmin")

	// Should get a 403 here as the NewRestClient attempts to authenticate.
	expect403(c, err)

	// Should not be allowed to get a configuration of a service
	_, err = wrongPassClient.GetServiceConfig("ipam")
	expect403(c, err)

	// Getting root's index is fine
	err = wrongPassClient.Get("/", &r)
	if err != nil {
		c.Fatal(err)
	}
	fmt.Println("Received: ", r)
	svcName = r.ServiceName
	fmt.Printf("Service name: %s", svcName)

	if svcName != common.ServiceNameRoot {
		c.Fatalf("Expected serviceName to be %s, got %s", common.ServiceNameRoot, svcName)
	}

	// 3. Client in admin role.
	adminClient, err := s.getClientForTestAuth(c, "admin", "password")
	if err != nil {
		c.Fatal(err)
	}

	err = adminClient.Get("", &r)
	if err != nil {
		c.Fatal(err)
	}
	fmt.Println("Received: ", r)
	svcName = r.ServiceName
	fmt.Printf("Service name: %s", svcName)

	if svcName != common.ServiceNameRoot {
		c.Fatalf("Expected serviceName to be %s, got %s", common.ServiceNameRoot, svcName)
	}

	// 4. Client in tenant role.
	tenant1Client, err := s.getClientForTestAuth(c, "tenant1", "password")
	err = tenant1Client.Get("", &r)
	if err != nil {
		c.Fatal(err)
	}
	tenant2Client, err := s.getClientForTestAuth(c, "tenant2", "password")
	err = tenant1Client.Get("", &r)
	if err != nil {
		c.Fatal(err)
	}

	_, err = tenant1Client.GetServiceConfig("ipam")
	expect403(c, err)

	// Let's start a tenant service
	ten := &tenant.TenantSvc{}
	serviceCred := common.Credential{Type: common.CredentialUsernamePassword,
		Username: "service",
		Password: "password",
	}
	err = common.SimpleOverwriteSchema(ten, s.rootURL, &serviceCred)
	if err != nil {
		c.Fatal(err)
	}
	tenantInfo, err := common.SimpleStartService(ten, s.rootURL, &serviceCred)
	if err != nil {
		c.Fatal(err)
	}
	_ = <-tenantInfo.Channel
	tenURL := fmt.Sprintf("http://%s", tenantInfo.Address)

	// We are going to try to add a couple of tenants.
	tenant1 := tenant.Tenant{Name: "tenant1", ExternalID: "tenant1"}
	tenant2 := tenant.Tenant{Name: "tenant2", ExternalID: "tenant2"}

	// Tenant client should not be able to add a tenant
	tenOut := &tenant.Tenant{}
	err = tenant1Client.Post(fmt.Sprintf("%s/tenants", tenURL), tenant1, tenOut)
	expect403(c, err)

	// Admin client should add them fine.
	err = adminClient.Post(fmt.Sprintf("%s/tenants", tenURL), tenant1, tenOut)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(tenOut.ID, check.Equals, uint64(1))
	err = adminClient.Post(fmt.Sprintf("%s/tenants", tenURL), tenant2, tenOut)
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(tenOut.ID, check.Equals, uint64(2))

	// Now there are 2 tenants...
	// Can tenant1 access tenant2's segments?
	var segs []tenant.Segment
	err = tenant1Client.Get(fmt.Sprintf("%s/tenants/%d/segments", tenURL, 2), segs)
	expect403(c, err)

	// And vice versa
	err = tenant2Client.Get(fmt.Sprintf("%s/tenants/%d/segments", tenURL, 1), segs)
	expect403(c, err)

	// Admin should be good
	err = adminClient.Get(fmt.Sprintf("%s/tenants/%d/segments", tenURL, 1), segs)
	// There are no segments, so we should expect a 404
	common.ExpectHttpError(c, err, http.StatusNotFound)

}

// Test the service list.
func (s *MySuite) TestServiceList(c *check.C) {
	fmt.Println("Entering TestServiceList")
	dir, _ := os.Getwd()
	fmt.Println("In", dir)

	err := s.RomanaTestSuite.MockConfig(common.DefaultTestConfigFile)
	if err != nil {
		c.Fatal(err)
	}
	fmt.Printf("Calling Run(%s)", s.RomanaTestSuite.ConfigFile)
	svcInfo, err := Run(s.RomanaTestSuite.ConfigFile)
	if err != nil {
		c.Fatal(err)
	}

	fmt.Println("Waiting for message")
	msg := <-svcInfo.Channel
	fmt.Println("Root service said:", msg)

	rootURL := fmt.Sprintf("http://%s", svcInfo.Address)
	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL, nil))
	if err != nil {
		c.Fatal(err)
	}
	r := common.IndexResponse{}
	err = client.Get("", &r)
	if err != nil {
		c.Fatal(err)
	}
	fmt.Println("Received: ", r)
	svcName := r.ServiceName
	fmt.Printf("Service name: %s", svcName)

	if svcName != common.ServiceNameRoot {
		c.Fatalf("Expected serviceName to be %s, got %s", common.ServiceNameRoot, svcName)
	}
}
