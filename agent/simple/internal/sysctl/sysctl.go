// Copyright (c) 2017 Pani Networks
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

package sysctl

import (
	"bytes"
	"io/ioutil"
	"strings"
)

// Set systcl value to 1, the specified path has to start with /proc/sys.
// Example: /proc/sys/net/ipv4/conf/default/proxy_arp
func Set(path string) error {
	if !strings.HasPrefix(path, "/proc/sys") {
		return errorSetBoundary("systl.Set() called with path outside of /proc/sys")
	}

	return ioutil.WriteFile(path, []byte("1"), 0644)
}

// errorSetBoundary indicates that Set function got called
// with invalid path.
type errorSetBoundary string

func (e errorSetBoundary) Error() string { return string(e) }

// Check that sysctl value is 1, the specified path has to start with /proc/sys.
// For paths outside of /proc/sys result is undetermented.
func Check(path string) (bool, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return false, err
	}

	if bytes.Equal(data, []byte("1\n")) {
		return true, nil
	}

	return false, nil
}
