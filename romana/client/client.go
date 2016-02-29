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

// Package client implements glue code for multiple
// platforms like openstack and kubernetes.
package client

import (
	"errors"

	"github.com/romana/core/romana/kubernetes"
	"github.com/romana/core/romana/openstack"

	"github.com/spf13/viper"
)

// GetTenantName returns openstack tenant name corresponding
// to the UUID being used in romana tenants.
func GetTenantName(uuid string) (string, error) {
	if platform := viper.GetString("Platform"); platform == "kubernetes" {
		return kubernetes.GetTenantName(uuid)
	} else if platform == "openstack" {
		return openstack.GetTenantName(uuid)
	} else {
		// Unimplemented Platform.
		return "", errors.New("Unimplemented Platform.")
	}
}

// TenantExists returns true/false depending on
// openstack tenant name or uuid exists or not.
func TenantExists(name string) bool {
	if platform := viper.GetString("Platform"); platform == "kubernetes" {
		return kubernetes.TenantExists(name)
	} else if platform == "openstack" {
		return openstack.TenantExists(name)
	} else {
		// Unimplemented Platform.
		return false
	}
}

// GetTenantUUID returns openstack tenant UUID corresponding to the name.
func GetTenantUUID(name string) (string, error) {
	if platform := viper.GetString("Platform"); platform == "kubernetes" {
		return kubernetes.GetTenantUUID(name)
	} else if platform == "openstack" {
		return openstack.GetTenantUUID(name)
	} else {
		// Unimplemented Platform.
		return "", errors.New("Unimplemented Platform.")
	}
}
