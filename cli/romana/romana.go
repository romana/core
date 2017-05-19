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

// Package romana contains romana/core related features which
// interact with the root/tenant/ipam/tenant and other related
// romana services.
package romana

import (
	"errors"
	"github.com/romana/core/common"
)

// reverse returns a given element in reverse
// order from a tenant.Tenant slice
func reverse(t []common.Tenant) chan common.Tenant {
	r := make(chan common.Tenant)
	go func() {
		for i, _ := range t {
			r <- t[len(t)-1-i]
		}
		close(r)
	}()
	return r
}

// GetTenantID return romana Tenant ID
// corresponding to romana name.
func GetTenantID(client *common.RestClient, name string) (uint64, error) {
	tenantURL, err := client.GetServiceUrl("tenant")
	if err != nil {
		return 0, err
	}

	tenants := []common.Tenant{}
	err = client.Get(tenantURL+"/tenants", &tenants)
	if err != nil {
		return 0, err
	}

	for t := range reverse(tenants) {
		if t.Name == name {
			return t.ID, nil
		}
	}

	return 0, errors.New("Romana Tenant ID not found.")
}
