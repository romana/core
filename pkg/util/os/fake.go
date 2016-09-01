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
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// FakeFile implements OSFile.
type FakeFile struct {
	io.Reader
	Content string
}

// Close is a no op to satisfy OSFile.
func (f FakeFile) Close() error {
	return nil
}

func (f FakeFile) Seek(int64, int) (int64, error) {
	return 0, nil
}

func (f *FakeFile) Stat() (os.FileInfo, error) {
	fi := FakeFileInfo{size: f.Size()}
	return fi, nil
}


func (f FakeFile) Truncate(size int64) error {
	return nil
}

func (f FakeFile) Sync() error {
	return nil
}

func (f *FakeFile) Size() int64 {
	return int64(len(f.Content))
}

// Write is a method of FakeFile that records all data it receives.
func (f *FakeFile) Write(p []byte) (ret int, err error) {
	f.Content = fmt.Sprintf("%s%s", f.Content, string(p))
	ret = len(p)
	return ret, nil
}

// FakeOS implements OS.
type FakeOS struct {
	FakeData string
	FakeFile *FakeFile
}

// open returns a FakeFile stuffed with fake data
func (o FakeOS) Open(name string) (OSFile, error) {
	fake := FakeFile{strings.NewReader(o.FakeData), ""}
	return &fake, nil
}

// appendFile returns a FakeFile implementation
// that will record any data it receives for later analisis.
func (o *FakeOS) AppendFile(name string) (OSFile, error) {
	fake := FakeFile{strings.NewReader(o.FakeData), ""}
	o.FakeFile = &fake
	return &fake, nil
}

// createIfMissing No op in tests.
func (o *FakeOS) CreateIfMissing(name string) error {
	return nil
}

type FakeFileInfo struct {
	size int64
}

func (f FakeFileInfo) Name() string {
	return "Fake file"
}


func (f FakeFileInfo) Size() int64 {
	return f.size
}

func (f FakeFileInfo) Mode() os.FileMode  {
	return os.ModeTemporary
}

func (f FakeFileInfo) ModTime() time.Time {
	return time.Now()
}

func (f FakeFileInfo) IsDir() bool {
	return false
}

func (f FakeFileInfo) Sys() interface{} {
	return nil
}

