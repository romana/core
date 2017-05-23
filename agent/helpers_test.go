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
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// helpers_test.go contains tests cases for helpers
package agent

import (
	"fmt"
	"net"
	"strings"
	"testing"

	utilexec "github.com/romana/core/agent/exec"
	utilos "github.com/romana/core/pkg/util/os"
)

// TestAppendLineToFile writes data to fake file and ensures it's got written.
func TestAppendLineToFile(t *testing.T) {
	/*
	   Mocking framework comments

	   Framework is available via AgentHelperT structure
	   that must be initialized with mocking interfaces.

	   * new(AgentHelperT) returns uninitialized AgentHelperT
	   * AgentHelperT.Executor not used in this test so we initialize it with
	     default implementation
	   * AgentHelperT.OS initialized with utilos.FakeOS that implements
	     appendFile (used by appendLineToFile)
	   * Data written by appendLineToFile available via OS.fakeFile.content
	*/

	// Init fake helpe, &leasefiler
	fOS := &utilos.FakeOS{}
	helper := Helper{OS: fOS}
	agent := Agent{Helper: &helper}

	// when
	netif := NewNetIf("eth0", "A", "127.0.0.1")
	lease := fmt.Sprintf("%s %s", netif.Mac, netif.IP)
	_ = agent.Helper.appendLineToFile("stub", lease)

	// expect
	get := fOS.FakeFile.Content
	if get != fmt.Sprintf("%s\n", lease) {
		t.Errorf("AppendLineToFile failed, expect %s\\n, got %q", lease, get)
	}
}

// TestIsLineInFile is checking that isLineInFile correctly detect presence of
// given line in the file.
func TestIsLineInFile(t *testing.T) {
	// Returning correct lease via utilos.FakeOS
	fOS := &utilos.FakeOS{FakeData: "A 127.0.0.1"}
	agent := Agent{Helper: &Helper{OS: fOS}}

	// NetIf to make a lease from
	ip := "127.0.0.1"
	netif := NewNetIf("eth0", "A", ip)

	lease := fmt.Sprintf("%s %s", netif.Mac, netif.IP)

	// we don't care for lease file name in this test so it's just "stub"
	out, err := agent.Helper.isLineInFile("stub", lease)

	// expect
	if err != nil {
		t.Error("IsLineInFile unknown error", err)
	}
	if out != true {
		t.Errorf("IsLineInFile failed, got %t, expect true", out)
	}

	// when

	// NetIf to make a lease from
	netif = NewNetIf("eth0", "A", ip)

	// Returning wrong lease via utilos.FakeOS
	fOS = &utilos.FakeOS{FakeData: "C 127.0.0.1"}
	agent.Helper.OS = fOS
	lease = fmt.Sprintf("%s %s", netif.Mac, netif.IP)

	// we don't care for lease file name in this test so it's just "stub"
	out, err = agent.Helper.isLineInFile("stub", lease)

	// expect
	if err != nil {
		t.Error("IsLineInFile unknown error", err)
	}

	if out == true {
		t.Errorf("IsLineInFile failed, got %t, expect false", out)
	}
}

// TestDhcpPid is checking that DhcpPid is successfully detecting
// running DHCP server.
func TestDhcpPid(t *testing.T) {
	agent := Agent{Helper: &Helper{}}
	// when

	// DhcpPid is expecting pid in stdout
	E := &utilexec.FakeExecutor{Output: []byte("12345")}
	agent.Helper.Executor = E
	out, err := agent.Helper.DhcpPid()
	// expect
	if err != nil {
		t.Error("DhcpPid() failed with", err)
	}
	if out != 12345 {
		t.Error("DhcpPid() returned wrong pid: expected 12345, got", out)
	}

	// when

	// Here testing that DhcpPid's sanity check - pid must be < 65535
	E = &utilexec.FakeExecutor{Output: []byte("1234567")}
	agent.Helper.Executor = E
	out, err = agent.Helper.DhcpPid()
	// expect
	if err == nil {
		t.Error("DhcpPid() failed to detect error condition pid > 65535")
	}
}

// TestIsRouteExist is checking that isRouteExist detects correctly if given
// ip route already exist.
func TestIsRouteExist(t *testing.T) {
	agent := Agent{Helper: &Helper{}}
	// when

	// IsRouteExist treats non empty output as a success
	E := &utilexec.FakeExecutor{Output: []byte("route exist")}
	agent.Helper.Executor = E
	ip := net.ParseIP("127.0.0.1")
	err := agent.Helper.isRouteExist(ip, "32")

	// expect
	if err != nil {
		t.Errorf("TestIsRouteExist failed with %q", err)
	}

	expect := "/sbin/ip ro show 127.0.0.1/32"
	got := *E.Commands
	if expect != got {
		t.Errorf("TestIsRouteExist returned unexpected command, expect %s, got %s", expect, got)
	}

	// when
	// for this test we want to fail isRouteExist by providing nil output
	E = &utilexec.FakeExecutor{}
	agent.Helper.Executor = E
	err = agent.Helper.isRouteExist(ip, "32")

	// expect
	if err == nil {
		t.Error("TestIsRouteExist failed to detect 'No such route' condition")
	}
}

// TestCreateRoute is checking that createRoute generates correct OS commands
// to create ip routes for given endopoint.
func TestCreateRoute(t *testing.T) {
	agent := Agent{Helper: &Helper{}}
	// when

	// we only care for recorded commands, no need for fake output or errors
	E := &utilexec.FakeExecutor{}
	agent.Helper.Executor = E
	ip := net.ParseIP("127.0.0.1")
	_ = agent.Helper.createRoute(ip, "0", "dev", "eth0")

	// expect
	expect := "/sbin/ip ro add 127.0.0.1/0 dev eth0"
	got := *E.Commands
	if expect != got {
		t.Errorf("TestIsRouteExist returned unexpected command, expect %s, got %s", expect, got)
	}
}

// TestCreateInterhostRoutes is checking that ensureInterHostRoutes generates
// correct commands to create IP routes to other romana hosts.
func TestCreateInterhostRoutes(t *testing.T) {
	agent := mockAgent()
	// when

	// we only care for recorded commands, no need for fake output or errors
	E := &utilexec.FakeExecutor{}
	agent.Helper.Executor = E
	_ = agent.Helper.ensureInterHostRoutes()

	// expect
	expect := strings.Join([]string{"/sbin/ip ro show 10.65.0.0/16",
		"/sbin/ip ro add 10.65.0.0/16 via 192.168.0.12"}, "\n")
	got := *E.Commands
	if expect != got {
		t.Errorf("TestCreateInterhostRoutes returned unexpected command, expect %s, got %s", expect, got)
	}
}

// TODO this test uses real file which might not work in many cases.
// Need to improve test framework to support proper read/write calls.
func TestRemoveLineFromFile(t *testing.T) {
	const (
		data = `fa:16:3e:05:0c:c1 10.0.0.1
fa:16:3e:05:0c:c2 10.0.0.2
fa:16:3e:05:0c:c3 10.0.0.3
`
		filename = "/tmp/testfile_1234afasdf"
	)

	fOS := &utilos.DefaultOS{}
	helper := Helper{OS: fOS}
	agent := Agent{Helper: &helper}

	err := agent.Helper.OS.CreateIfMissing(filename)
	if err != nil {
		t.Errorf("%s", err)
	}

	file, err := agent.Helper.OS.AppendFile(filename)
	if err != nil {
		t.Errorf("%s", err)
	}

	defer file.Close()
	d := []byte(data)
	_, err = file.Write(d)
	if err != nil {
		t.Errorf("%s", err)
	}

	err = file.Sync()
	if err != nil {
		t.Errorf("%s", err)
	}

	// when
	netif := NewNetIf("eth0", "fa:16:3e:05:0c:c2", "10.0.0.2")
	lease := fmt.Sprintf("%s %s", netif.Mac, netif.IP)
	_ = agent.Helper.removeLineFromFile(filename, lease)

	// expect
	ok, err := agent.Helper.isLineInFile(filename, lease)
	if err != nil || ok {
		t.Errorf("removeLineFromFile failed, line still in file = %t, error = %s", ok, err)
	}
}
