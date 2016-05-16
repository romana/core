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

// Package kubernetes implements kubernetes API specific
// helper functions.
package kubernetes

import (
	"github.com/romana/core/romana/util"
)

// GetTenantName returns kubernetes tenant name corresponding
// to the UUID being used in romana tenants.
func GetTenantName(uid string) (string, error) {
	return "", util.ErrUnimplementedFeature
}

// TenantExists returns true/false depending on
// kubernetes tenant name or uuid exists.
func TenantExists(name string) bool {
	// Unimplemented
	return false
}

// GetTenantUUID returns kubernetes tenant
// UUID corresponding to the name.
func GetTenantUUID(name string) (string, error) {
	return "", util.ErrUnimplementedFeature
}

// CreateTenant creates kubernetes specific tenant
// corresponding to the name given.
func CreateTenant(name string) error {
	return util.ErrUnimplementedFeature
}
