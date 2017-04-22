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

// Package defines interface for publishing networks via dynamic routing
// protocols.
package publisher

import (
	"net"
)

type Config map[string]string

func (c Config) SetDefault(key, defaultValue string) string {
	if configValue, ok := c[key]; ok {
		return configValue
	}

	return defaultValue
}

type Interface interface {
	// Updates list of networks advertised via routing protocol.
	Update([]net.IPNet) error
}
