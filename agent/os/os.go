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

package os

import (
	"io"
	"os"
)

// OS interface is a facade to standard lib os.
type OS interface {
	Open(name string) (OSFile, error)
	AppendFile(name string) (OSFile, error)
	CreateIfMissing(name string) error
}

// OSFile interface is a facade to os.File
type OSFile interface {
	io.Reader
	io.Writer
	io.Closer
	io.Seeker
	Stat() (os.FileInfo, error)
	Truncate(size int64) error
	Sync() error
}

// DefaultOS is a default implementation of OS interface
// which proxies everything to standard lib.
type DefaultOS struct {
}

// open is a direct proxy to os.Open
func (DefaultOS) Open(name string) (OSFile, error) {
	f, err := os.OpenFile(name, os.O_RDWR, os.ModeAppend)
	return f, err
}

// appendFile returns a file opened for write
// with cursor positioned at the end of file.
func (DefaultOS) AppendFile(name string) (OSFile, error) {
	file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0600)
	return file, err
}

// createIfMissing tries create file if it's not there yet,
// otherwise no op.
func (DefaultOS) CreateIfMissing(name string) error {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}
