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

package tenant

import (
//	"database/sql"
	//	"github.com/romana/core/common"
)

// Backing store
type tenantStore interface {
	validateConnectionInformation() error
	connect() error
	createSchema(overwrite bool) error
	setConfig(config map[string]interface{}) error

	addTenant(tenant *Tenant) error
	findTenant(id uint64) (Tenant, error)
	addSegment(tenantId uint64, segment *Segment) error
	findSegment(tenantId uint64, id uint64) (Segment, error)
	
	listTenants() ([]Tenant, error)
	listSegments(tenantId uint64) ([]Segment, error)
}

type Tenant struct {
	Id       uint64 `sql:"AUTO_INCREMENT"`
	Name     string
	Segments []Segment
	Seq      uint64
}

type Segment struct {
	Id       uint64 `sql:"AUTO_INCREMENT"`
	TenantId uint64
	Name     string
	Seq      uint64
}
