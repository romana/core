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

package exec

import (
	"fmt"
	"io"
	"strings"
)

// FakeExecutor implements Executable
// stores faked Output, Error and commands recorded by Exec.
type FakeExecutor struct {
	Output   []byte
	Error    error
	Commands *string
}

// Fakemd implement Cmd interface for testing purposes.
type FakeCmd struct{}

func (FakeCmd) StdinPipe() (io.WriteCloser, error) {
	// TODO
	return nil, nil
}

func (FakeCmd) CombinedOutput() ([]byte, error) {
	// TODO
	var empty []byte
	return empty, nil
}

func (FakeCmd) Start() error {
	return nil
}

func (FakeCmd) Wait() error {
	return nil
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

func (x *FakeExecutor) Cmd(cmd string, args []string) Cmd {
	return FakeCmd{}
}
