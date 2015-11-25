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
package agent

// This file contins Helper structure with interfaces which which is used
// to interact with operation system.
//
// - OS interface used to access filesystem, write and read files.
// - Executable interface is used to execute commands in operation system.
//
// Both interfaces has default and fake implementations, default implementation
// will usually just proxy calls to standard library while test implemetation
// will allow mocking all interactions.

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"net"
	"github.com/romana/core/common"
	"github.com/romana/core/topology"
)

// TODO There is a tradeoff, either use global variable for provider
// or pass provider down to each method.
// Passing down to each method is more explicit which is good,
// but pollutes method's signatures too much. Need to have a discussion.

// Helper groups testable implementations
// of standard library functions.
type Helper struct {
	Executor                   Executable
	OS                         OS
	Agent                      *Agent //access field for Agent
	ensureRouteToEndpointMutex *sync.Mutex
	ensureLineMutex            *sync.Mutex
	ensureInterHostRoutesMutex *sync.Mutex
}

// mockAgent creates the agent with the configuration 
// needed for tests without the need to go through 
// configuration files. 
func mockAgent() Agent {

	host0 := common.HostMessage{Ip: "172.17.0.1", RomanaIp: "127.0.0.1/8"}
	
	romanaIp, romanaNet, _ := net.ParseCIDR(host0.RomanaIp)
	networkConfig  := &NetworkConfig{}
	networkConfig.currentHostIP = net.ParseIP(host0.Ip)
	networkConfig.currentHostGW = romanaIp
	networkConfig.currentHostGWNet = *romanaNet
	networkConfig.currentHostGWNetSize, _ = romanaNet.Mask.Size()
	networkConfig.currentHostIndex = 0
	
	host1 := common.HostMessage{Ip: "192.168.0.12", RomanaIp: "10.65.0.0/16"}
	networkConfig.hosts = []common.HostMessage{ host0, host1}
	
	dc := topology.Datacenter{}
	dc.Cidr = "10.0.0.0/8"
	dc.PortBits = 8
	dc.TenantBits = 4
	dc.SegmentBits = 4
	dc.EndpointSpaceBits = 0
	dc.EndpointBits = 8
	
	networkConfig.dc = dc
	
	agent := &Agent{networkConfig: networkConfig}
	helper := NewAgentHelper(agent)
	agent.Helper = &helper

	return *agent
}

// Executable is an interface that mocks exec.Command().Output()
type Executable interface {
	Exec(cmd string, args []string) ([]byte, error)
}

// DefaultExecutor is a default implementation of Executable that passes
// back to standard library.
type DefaultExecutor struct{}

// Exec is a method of DefaultExecutor which proxies all requests to exec.Command()
func (DefaultExecutor) Exec(cmd string, args []string) ([]byte, error) {
	log.Printf("Helper.Executor: executing command: %s %s", cmd, args)
	out, err := exec.Command(cmd, args...).Output()
	return out, err
}

// OS interface mocks standard lib os.
type OS interface {
	open(name string) (OSFile, error)
	appendFile(name string) (OSFile, error)
	createIfMissing(name string) error
}

// OSFile interface mocks os.File
type OSFile interface {
	io.Reader
	io.Writer
	io.Closer
}

// DefaultOS is a default implementation of OS interface
// which proxyes everything to standard lib.
type DefaultOS struct {
}

// open is a direct proxy to os.Open
func (DefaultOS) open(name string) (OSFile, error) {
	f, err := os.Open(name)
	return f, err
}

// appendFile returns a file opened for write
// with cursor positioned at the end of file.
func (DefaultOS) appendFile(name string) (OSFile, error) {
	file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0600)
	return file, err
}

// createIfMissing tries create file if it's not there yet,
// otherwise no op.
func (DefaultOS) createIfMissing(name string) error {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

// FakeFile implements OSFile.
type FakeFile struct {
	io.Reader
	content string
}

// Close is a no op to satisfy OSFile.
func (f FakeFile) Close() error {
	return nil
}

// Write is a method of FakeFile that records all data it receives.
func (f *FakeFile) Write(p []byte) (ret int, err error) {
	f.content = fmt.Sprintf("%s%s", f.content, string(p))
	ret = len(p)
	return ret, nil
}

// FakeOS implements OS.
type FakeOS struct {
	fakeData string
	fakeFile *FakeFile
}

// open is a method of FakeOS that will pass a structure that will return
// a file stuffed with fake data.
func (o FakeOS) open(name string) (OSFile, error) {
	fake := FakeFile{strings.NewReader(o.fakeData), ""}
	return &fake, nil
}

// appendFile is a method of FakeOS that returns a FakeFile implementation
// that will record any data it receives for later analisis.
func (o *FakeOS) appendFile(name string) (OSFile, error) {
	fake := FakeFile{strings.NewReader(o.fakeData), ""}
	o.fakeFile = &fake
	return &fake, nil
}

// createIfMissing No op in tests.
func (o *FakeOS) createIfMissing(name string) error {
	return nil
}

// FakeExecutor implements Executable
// stores faked Output, Error and commands recorded by Exec.
type FakeExecutor struct {
	Output   []byte
	Error    error
	Commands *string
}

// Exec is a method of fake executor that will record all incoming commands
// and use faked Output and Error.
func (x *FakeExecutor) Exec(cmd string, args []string) ([]byte, error) {
	var c string
	if x.Commands == nil {
		c = fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))
	} else {
		c = fmt.Sprintf("%s\n%s %s", *x.Commands, cmd, strings.Join(args, " "))
	}
	x.Commands = &c
	return x.Output, x.Error
}
